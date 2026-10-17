// Runs security tests T1-T8 (plus extra negative tests) against a fresh copy of the portal
// in a real Chrome browser, and writes the evidence to ./evidence/.
//
//   npm run evidence              uses your installed Google Chrome
//   HEADED=1 npm run evidence     watch it happen
//   CHROME_PATH=/path/to/chrome npm run evidence
//
// Passkeys are created by Chrome's built-in virtual authenticator (DevTools WebAuthn domain),
// a software authenticator that performs the same WebAuthn ceremony as Touch ID.
// The server verifies every response exactly as it does for a real device.
// It uses its own database (data/evidence.db), so your normal data/portal.db is untouched.

import { chromium } from 'playwright-core';
import { mkdirSync, rmSync, writeFileSync, createWriteStream } from 'node:fs';
import { DatabaseSync } from 'node:sqlite';
import { seed } from './seed.js';
import { unassign } from './admin.js';
import { createApp } from '../server.js';

const PORT = Number(process.env.EVIDENCE_PORT || 3000);
const OUT = 'evidence';
const DB_PATH = 'data/evidence.db';

rmSync(OUT, { recursive: true, force: true });
mkdirSync(OUT, { recursive: true });

const codes = seed(DB_PATH);
const logStream = createWriteStream(`${OUT}/server.log`);
const { app, origin } = createApp({ dbPath: DB_PATH, port: PORT, logStream });
const server = await new Promise((ok, fail) => { const s = app.listen(PORT, () => ok(s)); s.on('error', fail); })
  .catch((e) => { console.error(`Cannot start on port ${PORT} (${e.code}). Stop "npm start" first, or set EVIDENCE_PORT.`); process.exit(1); });
const db = new DatabaseSync(DB_PATH);   // second connection, like a separate admin console
const grade = (s, c) => db.prepare('SELECT grade FROM enrollments WHERE student_id = ? AND course_id = ?').get(s, c)?.grade;

const results = [];
const requestLog = [];
function record(r) {
  results.push(r);
  console.log(`${r.pass ? 'PASS' : 'FAIL'}  ${r.test.padEnd(4)} ${r.identity.padEnd(8)} ${r.action}  ->  ${r.observed}`);
}
const short = (s, n = 24) => (s && s.length > n ? `${s.slice(0, n)}...` : s);
function summariseBody(raw) {
  if (!raw) return '';
  try {
    const b = JSON.parse(raw);
    if (b.response) return JSON.stringify({ id: short(b.id, 12), type: b.type,
      response: Object.fromEntries(Object.entries(b.response).map(([k, v]) => [k, typeof v === 'string' ? short(v, 16) : v])) });
    if (b.code) b.code = '<redacted>';   // never write a credential into a log
    return JSON.stringify(b);
  } catch { return short(raw, 80); }
}

async function launch() {
  const headless = !process.env.HEADED;
  if (process.env.CHROME_PATH) return chromium.launch({ executablePath: process.env.CHROME_PATH, headless });
  for (const channel of ['chrome', 'msedge']) {
    try { return await chromium.launch({ channel, headless }); } catch { /* try next */ }
  }
  throw new Error('Google Chrome not found. Install Chrome, or set CHROME_PATH to a Chromium-based browser.');
}

// A browser profile with its own cookies and its own virtual authenticator (one person, one device).
async function person(browser, label) {
  const context = await browser.newContext({ baseURL: origin, viewport: { width: 1100, height: 720 } });
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: {
    protocol: 'ctap2', transport: 'internal', hasResidentKey: true,
    hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  page.on('response', async (res) => {
    const req = res.request();
    if (!res.url().startsWith(origin) || req.resourceType() === 'stylesheet' || req.resourceType() === 'script') return;
    requestLog.push(`[${label}] ${req.method()} ${new URL(res.url()).pathname} -> ${res.status()}  ${summariseBody(req.postData())}`);
  });
  return { context, page, label };
}

// fetch() from inside the signed-in page: same cookie, same origin, exactly what DevTools console would do.
const call = (page, method, url, body) => page.evaluate(async ({ method, url, body }) => {
  const r = await fetch(url, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, body: await r.text() };
}, { method, url, body });
const logCall = (label, method, url, body, r) => requestLog.push(`[${label}] ${method} ${url} -> ${r.status}  ${body ? JSON.stringify(body) : ''}  response=${short(r.body, 120)}`);

async function enrollAndRegister(p, id) {
  await p.page.goto('/');
  await p.page.click('#enroll > summary');
  await p.page.fill('#enroll-id', id);
  await p.page.fill('#enroll-code', codes[id]);
  await p.page.click('#enroll-submit');
  await p.page.waitForSelector('#register-passkey', { state: 'visible' });
  const [res] = await Promise.all([
    p.page.waitForResponse((r) => r.url().endsWith('/webauthn/register/verify')),
    p.page.click('#register-passkey'),
  ]);
  await p.page.waitForFunction(() => document.getElementById('status').textContent.includes('Passkey saved'));
  return res;
}

async function signIn(p, id) {
  await p.page.goto('/');
  await p.page.fill('#signin-id', id);
  const [req, res] = await Promise.all([
    p.page.waitForRequest((r) => r.url().endsWith('/webauthn/login/verify')),
    p.page.waitForResponse((r) => r.url().endsWith('/webauthn/login/verify')),
    p.page.click('#signin-submit'),
  ]);
  return { req, res };
}

// Labelled screenshot: a caption bar at the top says which test, which identity and what the server returned.
async function shot(page, name, caption) {
  await page.evaluate((text) => {
    const bar = document.createElement('div');
    bar.textContent = text;
    Object.assign(bar.style, { background: '#202124', color: '#fff', font: '13px/1.5 ui-monospace, Menlo, monospace', padding: '8px 14px' });
    if (document.contentType === 'application/json') bar.style.marginTop = '32px';   // clear Chrome's JSON viewer toolbar
    document.body.prepend(bar);
  }, caption);
  await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true });
}

// Shows requests the test runner sent from inside the signed-in page (the same as typing them
// into the DevTools console) and the server's replies, so the screenshot records them.
async function annotate(page, heading, entries) {
  await page.evaluate(({ heading, entries }) => {
    const box = document.createElement('section');
    Object.assign(box.style, { maxWidth: '760px', margin: '0 auto 40px', padding: '16px 20px', background: '#fff',
      borderRadius: '12px', boxShadow: '0 0 0 2px #1c2733', font: '14px/1.5 -apple-system, system-ui, sans-serif' });
    const h = document.createElement('p');
    h.textContent = heading;
    Object.assign(h.style, { margin: '0 0 8px', fontWeight: '600' });
    box.append(h);
    for (const [req, res] of entries) {
      const pre = document.createElement('pre');
      pre.textContent = `> ${req}\n< ${res}`;
      Object.assign(pre.style, { margin: '8px 0 0', padding: '10px 12px', background: '#f3f5f7', borderRadius: '6px',
        whiteSpace: 'pre-wrap', font: '13px/1.5 ui-monospace, Menlo, monospace' });
      box.append(pre);
    }
    (document.querySelector('main') || document.body).after(box);
  }, { heading, entries });
}

let browser;
try {
  browser = await launch();
  const s1 = await person(browser, 'S001');

  // ---------- T1: S001 registers a passkey ----------
  const t1 = await enrollAndRegister(s1, 'S001');
  const pk = db.prepare('SELECT user_id, substr(id, 1, 10) AS cred, length(public_key) AS bytes FROM passkeys WHERE user_id = ?').get('S001');
  await shot(s1.page, 'T1-S001-registers-passkey', `T1 · S001 · POST /webauthn/register/verify -> ${t1.status()} · passkey stored for ${pk?.user_id} (credential ${pk?.cred}..., ${pk?.bytes}-byte public key)`);
  record({ test: 'T1', identity: 'S001', action: 'Enroll with one-time code, then register a passkey',
    expected: 'Credential stored for S001; public key server-side', observed: `${t1.status()} verified; passkeys row: user_id=${pk?.user_id}, credential ${pk?.cred}..., public key ${pk?.bytes} bytes`,
    http: t1.status(), pass: t1.status() === 200 && pk?.user_id === 'S001', evidence: 'T1-S001-registers-passkey.png' });

  // ---------- T2: S001 signs in ----------
  const t2 = await signIn(s1, 'S001');
  await s1.page.waitForURL('**/app');
  await s1.page.waitForSelector('#record');
  const me = await call(s1.page, 'GET', '/me');
  const replayBody = t2.req.postData();
  await shot(s1.page, 'T2-S001-signs-in', `T2 · S001 · POST /webauthn/login/verify -> ${t2.res.status()} · session created · GET /me -> ${me.status}`);
  record({ test: 'T2', identity: 'S001', action: 'Sign in with the registered passkey',
    expected: 'Fresh challenge verified; session created', observed: `${t2.res.status()} verified; GET /me -> ${me.status} ${me.body}`,
    http: t2.res.status(), pass: t2.res.status() === 200 && me.status === 200, evidence: 'T2-S001-signs-in.png' });

  // ---------- T3a: replay a captured sign-in response ----------
  await s1.page.click('#logout');
  await s1.page.waitForURL(`${origin}/`);
  const fresh = await call(s1.page, 'POST', '/webauthn/login/options', { userId: 'S001' });
  const replay = await s1.page.evaluate(async (body) => {
    const r = await fetch('/webauthn/login/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
    return { status: r.status, body: await r.text() };
  }, replayBody);
  logCall('S001', 'POST', '/webauthn/login/verify (replayed T2 body)', null, replay);
  const afterReplay = await call(s1.page, 'GET', '/me');
  await annotate(s1.page, 'Test runner: the T2 sign-in response, captured and sent again after logging out and requesting a fresh challenge', [
    ["fetch('/webauthn/login/verify', { method: 'POST', body: <captured T2 response> })", `${replay.status} ${replay.body}`],
    ["fetch('/me')", `${afterReplay.status} ${afterReplay.body}`]]);
  await shot(s1.page, 'T3a-replayed-response-rejected', `T3a · replayed T2 sign-in response -> ${replay.status} · GET /me -> ${afterReplay.status}, no session`);
  record({ test: 'T3a', identity: 'S001', action: 'Log out, get a fresh challenge, resend the captured T2 sign-in response',
    expected: 'Rejected; no session', observed: `${replay.status} ${JSON.parse(replay.body).reason}; GET /me -> ${afterReplay.status}`,
    http: replay.status, pass: fresh.status === 200 && replay.status === 400 && afterReplay.status === 401, evidence: 'T3a-replayed-response-rejected.png' });

  // ---------- T3b: tamper with the signature in a live sign-in ----------
  await s1.page.route('**/webauthn/login/verify', async (route) => {
    const body = JSON.parse(route.request().postData());
    const sig = body.response.signature;
    const i = Math.floor(sig.length / 2);
    body.response.signature = sig.slice(0, i) + (sig[i] === 'A' ? 'B' : 'A') + sig.slice(i + 1);  // flip one character
    await route.continue({ postData: JSON.stringify(body) });
  });
  const t3b = await signIn(s1, 'S001');
  await s1.page.waitForFunction(() => document.getElementById('status').textContent.includes('Sign-in failed'));
  await shot(s1.page, 'T3b-tampered-signature-rejected', `T3b · S001 · signature altered by one character · POST /webauthn/login/verify -> ${t3b.res.status()} · no session`);
  await s1.page.unroute('**/webauthn/login/verify');
  const t3bBody = await t3b.res.json();
  const afterTamper = await call(s1.page, 'GET', '/me');
  record({ test: 'T3b', identity: 'S001', action: 'Change one character of the signature in a live sign-in response',
    expected: 'Rejected; no session', observed: `${t3b.res.status()} ${t3bBody.reason}; GET /me -> ${afterTamper.status}`,
    http: t3b.res.status(), pass: t3b.res.status() === 400 && afterTamper.status === 401, evidence: 'T3b-tampered-signature-rejected.png' });

  // ---------- T4: no session ----------
  const anon = await browser.newContext({ baseURL: origin });
  const anonPage = await anon.newPage();
  const t4 = await anonPage.goto('/students/S001');
  await shot(anonPage, 'T4-no-session-401', `T4 · no session (fresh browser profile) · GET /students/S001 -> ${t4.status()}`);
  requestLog.push(`[anonymous] GET /students/S001 -> ${t4.status()}  response=${await t4.text()}`);
  record({ test: 'T4', identity: 'none', action: 'GET /students/S001 with no session (fresh browser profile)',
    expected: 'Denied (401)', observed: `${t4.status()} ${await t4.text()}`, http: t4.status(), pass: t4.status() === 401, evidence: 'T4-no-session-401.png' });

  // ---------- T5: own record ----------
  await signIn(s1, 'S001');
  await s1.page.waitForURL('**/app');
  await s1.page.waitForSelector('#record');
  const t5 = await call(s1.page, 'GET', '/students/S001');
  logCall('S001', 'GET', '/students/S001', null, t5);
  await shot(s1.page, 'T5-S001-reads-own-record', `T5 · S001 · GET /students/S001 -> ${t5.status} · own record shown`);
  record({ test: 'T5', identity: 'S001', action: 'GET /students/S001 (own record)', expected: 'Allowed (200)',
    observed: `${t5.status} ${short(t5.body, 90)}`, http: t5.status, pass: t5.status === 200, evidence: 'T5-S001-reads-own-record.png' });

  // ---------- T6: another student's record, by URL and by fetch ----------
  const t6url = await s1.page.goto('/students/S002');
  await shot(s1.page, 'T6-S001-reads-S002-403', `T6 · signed in as S001 · URL edited to GET /students/S002 -> ${t6url.status()} (the UI offers no such link)`);
  await s1.page.goto('/app');
  const t6 = await call(s1.page, 'GET', '/students/S002');
  logCall('S001', 'GET', '/students/S002', null, t6);
  record({ test: 'T6', identity: 'S001', action: 'GET /students/S002 by editing the URL, then by fetch()',
    expected: 'Denied by server (403)', observed: `URL ${t6url.status()}; fetch ${t6.status} ${t6.body}`,
    http: t6.status, pass: t6url.status() === 403 && t6.status === 403, evidence: 'T6-S001-reads-S002-403.png' });

  // ---------- T7: student calls the lecturer grade endpoint ----------
  const before = grade('S002', 'C101');
  const t7body = { grade: 'E', role: 'lecturer', userId: 'L001' };   // identity claims in the body are ignored
  const t7 = await call(s1.page, 'POST', '/courses/C101/grades/S002', t7body);
  logCall('S001', 'POST', '/courses/C101/grades/S002', t7body, t7);
  const after = grade('S002', 'C101');
  await annotate(s1.page, 'Test runner: requests sent from S001\'s signed-in page that the UI does not offer (same as typing them in the DevTools console)', [
    ["fetch('/students/S002')", `${t6.status} ${t6.body}`],
    [`fetch('/courses/C101/grades/S002', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '${JSON.stringify(t7body)}' })`, `${t7.status} ${t7.body}`],
    ['S002\'s C101 grade in the database', `${before} before, ${after} after`]]);
  await shot(s1.page, 'T6-T7-S001-direct-requests-denied', `T6 + T7 · signed in as S001 · GET /students/S002 -> ${t6.status} · POST /courses/C101/grades/S002 -> ${t7.status}, grade unchanged`);
  record({ test: 'T7', identity: 'S001', action: 'POST /courses/C101/grades/S002 by fetch() (body claims role=lecturer)',
    expected: 'Denied (403); grade unchanged', observed: `${t7.status} ${t7.body}; S002 C101 grade ${before} before, ${after} after`,
    http: t7.status, pass: t7.status === 403 && before === after, evidence: 'T6-T7-S001-direct-requests-denied.png' });

  // ---------- T8: lecturer updates a grade in their course ----------
  const l1 = await person(browser, 'L001');
  await enrollAndRegister(l1, 'L001');
  await signIn(l1, 'L001');
  await l1.page.waitForURL('**/app');
  await l1.page.waitForSelector('#roster-C101');
  const t8before = grade('S001', 'C101');
  await l1.page.selectOption('select[data-student="S001"][data-course="C101"]', 'A');
  const [t8] = await Promise.all([
    l1.page.waitForResponse((r) => r.url().endsWith('/courses/C101/grades/S001')),
    l1.page.click('button[data-save="C101:S001"]'),
  ]);
  await l1.page.waitForFunction(() => document.querySelector('[data-row-status="C101:S001"]').textContent.startsWith('Saved'));
  await shot(l1.page, 'T8-L001-updates-C101-grade', `T8 · L001 (teaches C101) · POST /courses/C101/grades/S001 -> ${t8.status()} · grade saved`);
  const t8after = grade('S001', 'C101');
  record({ test: 'T8', identity: 'L001', action: 'Change S001\'s C101 grade in the UI and save',
    expected: 'Allowed (200); lecturer-course link verified', observed: `${t8.status()}; S001 C101 grade ${t8before} -> ${t8after}; audit line written`,
    http: t8.status(), pass: t8.status() === 200 && t8after === 'A', evidence: 'T8-L001-updates-C101-grade.png, audit-log.txt' });

  // ---------- Extra negative and least-privilege tests ----------
  const x1 = await call(l1.page, 'POST', '/courses/C102/grades/S002', { grade: 'A' });
  logCall('L001', 'POST', '/courses/C102/grades/S002', { grade: 'A' }, x1);
  record({ test: 'X1', identity: 'L001', action: 'POST /courses/C102/grades/S002 (a course L001 does not teach)',
    expected: 'Denied (403)', observed: `${x1.status} ${x1.body}; S002 C102 grade still ${grade('S002', 'C102')}`, http: x1.status, pass: x1.status === 403 });

  const x2 = await call(l1.page, 'GET', '/students/S002');
  logCall('L001', 'GET', '/students/S002', null, x2);
  const x2courses = JSON.parse(x2.body).courses?.map((c) => c.courseId).join(', ');
  record({ test: 'X2', identity: 'L001', action: 'GET /students/S002 (S002 takes C101 and C102)',
    expected: 'Allowed, but only the C101 part', observed: `${x2.status}; courses returned: ${x2courses}`, http: x2.status, pass: x2.status === 200 && x2courses === 'C101' });

  const reuse = await call(l1.page, 'POST', '/enroll/start', { userId: 'S001', code: codes.S001 });
  logCall('L001-browser', 'POST', '/enroll/start (S001 code reused)', { userId: 'S001', code: '<used code>' }, reuse);
  record({ test: 'X3', identity: 'any', action: 'Reuse S001\'s enrollment code after T1', expected: 'Rejected (single use)',
    observed: `${reuse.status} ${reuse.body}`, http: reuse.status, pass: reuse.status === 400 });

  const noEnroll = await anonPage.goto('/webauthn/register/options');
  requestLog.push(`[anonymous] GET /webauthn/register/options -> ${noEnroll.status()}`);
  record({ test: 'X4', identity: 'none', action: 'GET /webauthn/register/options without enrolling', expected: 'Denied (401)',
    observed: `${noEnroll.status()} ${await noEnroll.text()}`, http: noEnroll.status(), pass: noEnroll.status() === 401 });

  await s1.page.click('#logout');
  await s1.page.waitForURL(`${origin}/`);
  const x5 = await call(s1.page, 'GET', '/students/S001');
  logCall('S001', 'GET', '/students/S001 (after logout)', null, x5);
  record({ test: 'X5', identity: 'S001', action: 'Log out, then GET /students/S001', expected: 'Denied (401)',
    observed: `${x5.status} ${x5.body}`, http: x5.status, pass: x5.status === 401 });

  // X7: one sign-in response sent twice at the same instant. A challenge is single use, so only one may succeed.
  let captured;
  await s1.page.route('**/webauthn/login/verify', async (route) => { captured = route.request().postData(); await route.abort(); });
  await s1.page.fill('#signin-id', 'S001');
  await s1.page.click('#signin-submit');
  await s1.page.waitForFunction(() => document.getElementById('status').textContent.includes('stopped'));
  await s1.page.unroute('**/webauthn/login/verify');
  const twice = await s1.page.evaluate(async (body) => {
    const send = () => fetch('/webauthn/login/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body }).then((r) => r.status);
    return Promise.all([send(), send()]);
  }, captured);
  requestLog.push(`[S001] POST /webauthn/login/verify x2 in parallel (same response) -> ${twice.join(', ')}`);
  record({ test: 'X7', identity: 'S001', action: 'Send one valid sign-in response twice in parallel', expected: 'Exactly one succeeds',
    observed: `statuses ${twice.join(' and ')}`, http: twice.join('/'), pass: twice.filter((x) => x === 200).length === 1 && twice.includes(400) });

  // ProSit 2 link: the "mover" case. Registrar removes L001 from C101 while L001 is still signed in.
  unassign(db, 'L001', 'C101');
  const x6 = await call(l1.page, 'POST', '/courses/C101/grades/S001', { grade: 'B' });
  logCall('L001', 'POST', '/courses/C101/grades/S001 (after unassign)', { grade: 'B' }, x6);
  const x6read = await call(l1.page, 'GET', '/students/S001');
  record({ test: 'X6', identity: 'L001', action: 'Registrar removes L001 from C101; L001 (still signed in) retries a C101 grade change',
    expected: 'Denied on the very next request', observed: `${x6.status} ${x6.body}; GET /students/S001 -> ${x6read.status}; grade still ${grade('S001', 'C101')}`,
    http: x6.status, pass: x6.status === 403 && x6read.status === 403 });
} finally {
  await browser?.close();
  // ---------- write evidence ----------
  const audits = db.prepare('SELECT at, actor_id, action, target, outcome, detail FROM audit_log ORDER BY id').all();
  writeFileSync(`${OUT}/audit-log.txt`, audits.map((a) =>
    `${a.at}  ${String(a.actor_id ?? '-').padEnd(17)} ${a.action.padEnd(17)} ${String(a.target ?? '-').padEnd(10)} ${a.outcome.padEnd(8)} ${a.detail ?? ''}`).join('\n') + '\n');
  writeFileSync(`${OUT}/requests.log`, requestLog.join('\n') + '\n');
  writeFileSync(`${OUT}/results.json`, JSON.stringify({ runAt: new Date().toISOString(), node: process.version, origin, results }, null, 2));
  const md = ['| Test | Identity | Request / action | Expected | Observed | HTTP | Result |', '| --- | --- | --- | --- | --- | --- | --- |',
    ...results.map((r) => `| ${r.test} | ${r.identity} | ${r.action} | ${r.expected} | ${r.observed.replaceAll('|', '/')} | ${r.http} | ${r.pass ? 'Pass' : 'FAIL'} |`)];
  writeFileSync(`${OUT}/results.md`, `Run ${new Date().toISOString()} on ${origin}, Node ${process.version}\n\n${md.join('\n')}\n`);
  server.close(); db.close(); logStream.end();
  const failed = results.filter((r) => !r.pass).length;
  console.log(`\n${results.length - failed}/${results.length} passed. Evidence written to ./${OUT}/`);
  process.exitCode = failed ? 1 : 0;
}
