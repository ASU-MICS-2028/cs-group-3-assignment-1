import express from 'express';
import session from 'express-session';
import { rateLimit } from 'express-rate-limit';
import { randomBytes, createHash, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { openDb } from './db.js';
import { createPolicy } from './policy.js';
import {
  RP_ID, RP_NAME, DEFAULT_PORT, originFor, IDLE_MINUTES,
  ENROLL_WINDOW_MINUTES, GRADES, DEFAULT_DB_PATH,
} from './config.js';

const ROOT = dirname(fileURLToPath(import.meta.url));
const ID_PATTERN = /^[A-Z]\d{3}$/;        // S001, L001
const COURSE_PATTERN = /^C\d{3}$/;       // C101
const CHALLENGE_TTL_MS = 2 * 60 * 1000;  // a challenge must be answered within 2 minutes
const SESSION_COOKIE = 'srp.sid';
// Library error messages can quote the challenge values; keep reasons readable without them.
const cleanReason = (msg) => String(msg).replace(/"[^"]{12,}"/g, '"..."');

export const hashCode = (code) => createHash('sha256').update(code.trim().toUpperCase()).digest('hex');

export function createApp({ dbPath = DEFAULT_DB_PATH, port = DEFAULT_PORT, logStream } = {}) {
  const ORIGIN = originFor(port);
  const db = openDb(dbPath);
  const policy = createPolicy(db);

  // ---------- logging: method, path, status and user only; never bodies, cookies or keys ----------
  const log = (line) => {
    const out = `[${new Date().toISOString()}] ${line}`;
    console.log(out);
    logStream?.write(out + '\n');
  };
  const insertAudit = db.prepare(
    'INSERT INTO audit_log (at, actor_id, action, target, outcome, detail) VALUES (?, ?, ?, ?, ?, ?)');
  const audit = (actor, action, target, outcome, detail = null) => {
    insertAudit.run(new Date().toISOString(), actor ?? null, action, target ?? null, outcome, detail);
    log(`AUDIT actor=${actor ?? '-'} action=${action} target=${target ?? '-'} outcome=${outcome}${detail ? ` detail="${detail}"` : ''}`);
  };

  // ---------- queries (all parameterised) ----------
  const q = {
    user: db.prepare('SELECT id, name, role, programme, year, webauthn_user_id FROM users WHERE id = ?'),
    code: db.prepare('SELECT code_hash, expires_at, used_at FROM enrollment_codes WHERE user_id = ?'),
    useCode: db.prepare(`UPDATE enrollment_codes SET used_at = ?
                          WHERE user_id = ? AND code_hash = ? AND used_at IS NULL AND expires_at > ?`),
    passkeysFor: db.prepare('SELECT id, transports FROM passkeys WHERE user_id = ?'),
    passkey: db.prepare('SELECT id, user_id, public_key, counter, transports FROM passkeys WHERE id = ?'),
    addPasskey: db.prepare(`INSERT INTO passkeys (id, user_id, public_key, counter, transports, device_type, backed_up, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
    touchPasskey: db.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?'),
    coursesTaught: db.prepare(`SELECT c.id, c.title FROM lecturer_courses lc JOIN courses c ON c.id = lc.course_id
                               WHERE lc.lecturer_id = ? ORDER BY c.id`),
    studentCourses: db.prepare(`SELECT e.course_id AS courseId, c.title, e.grade FROM enrollments e
                                JOIN courses c ON c.id = e.course_id WHERE e.student_id = ? ORDER BY e.course_id`),
    studentCoursesForLecturer: db.prepare(`SELECT e.course_id AS courseId, c.title, e.grade FROM enrollments e
                                JOIN courses c ON c.id = e.course_id
                                JOIN lecturer_courses lc ON lc.course_id = e.course_id AND lc.lecturer_id = ?
                                WHERE e.student_id = ? ORDER BY e.course_id`),
    roster: db.prepare(`SELECT u.id AS studentId, u.name, e.grade FROM enrollments e
                        JOIN users u ON u.id = e.student_id WHERE e.course_id = ? ORDER BY u.id`),
    grade: db.prepare('SELECT grade FROM enrollments WHERE student_id = ? AND course_id = ?'),
    setGrade: db.prepare('UPDATE enrollments SET grade = ? WHERE student_id = ? AND course_id = ?'),
  };

  const app = express();
  app.disable('x-powered-by');

  // ---------- security headers ----------
  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
    });
    next();
  });

  // ---------- request log ----------
  app.use((req, res, next) => {
    res.on('finish', () => log(`${req.method} ${req.path} -> ${res.statusCode} user=${req.user?.id ?? req.session?.user?.id ?? '-'}`));
    next();
  });

  // ---------- server-side session ----------
  const secret = process.env.SESSION_SECRET || randomBytes(32).toString('hex');
  if (!process.env.SESSION_SECRET) log('SESSION_SECRET not set: using a random secret for this run (sessions end on restart)');
  app.use(session({
    name: SESSION_COOKIE,
    secret,
    resave: false,
    saveUninitialized: false,
    rolling: true,                 // idle timeout: each request pushes expiry forward
    cookie: {
      httpOnly: true,              // not readable by page scripts
      sameSite: 'strict',          // not sent on cross-site requests (CSRF defence)
      secure: false,               // localhost runs on plain HTTP; set true behind HTTPS
      maxAge: IDLE_MINUTES * 60 * 1000,
    },
  }));

  app.use(express.json({ limit: '50kb' }));
  // State-changing requests must be JSON: an HTML form on another site cannot send that.
  app.use((req, res, next) => {
    if (req.method === 'POST' && !req.is('application/json')) return res.status(415).json({ error: 'Content-Type must be application/json' });
    next();
  });

  const regenerate = (req) => new Promise((ok, fail) => req.session.regenerate((e) => (e ? fail(e) : ok())));

  // ---------- rate limits (NIST SP 800-171: limit unsuccessful attempts) ----------
  // Only failed attempts count, so normal use is never throttled.
  const limiter = (limit) => rateLimit({ windowMs: 15 * 60 * 1000, limit, standardHeaders: 'draft-8', legacyHeaders: false,
    skipSuccessfulRequests: true, message: { error: 'Too many failed attempts. Wait 15 minutes and try again.' } });
  const enrollLimiter = limiter(10);
  const loginLimiter = limiter(30);

  // ---------- pending WebAuthn challenges ----------
  // Held on the server and removed synchronously the moment a response arrives,
  // so two parallel requests can never both use the same challenge.
  const pendingChallenges = new Map();   // sessionID -> { kind, challenge, userId, at }
  function issueChallenge(req, kind, challenge, userId) {
    for (const [id, p] of pendingChallenges) if (Date.now() - p.at > CHALLENGE_TTL_MS) pendingChallenges.delete(id);
    req.session.challengeIssued = Date.now();   // marks the session so its cookie is set
    pendingChallenges.set(req.sessionID, { kind, challenge, userId, at: Date.now() });
  }
  function takeChallenge(req, kind) {
    const p = pendingChallenges.get(req.sessionID);
    pendingChallenges.delete(req.sessionID);    // consumed before any await: single use
    if (!p || p.kind !== kind || Date.now() - p.at > CHALLENGE_TTL_MS) return null;
    return p;
  }
  // Route IDs are checked against a strict pattern before they reach the policy or the logs.
  const validIds = (...pairs) => pairs.every(([value, pattern]) => typeof value === 'string' && pattern.test(value));

  // ---------- authentication gate ----------
  // A request passes only with a session created by a verified passkey sign-in,
  // whose user and passkey still exist. Revoking the passkey ends the session.
  function requireAuth(req, res, next) {
    const s = req.session.user;
    const user = s && q.user.get(s.id);
    const key = s && q.passkey.get(s.credentialId);
    if (!user || !key || key.user_id !== user.id) {
      if (s) req.session.destroy(() => {});
      return res.status(401).json({ error: 'Not signed in' });
    }
    req.user = { id: user.id, role: user.role, name: user.name }; // role read fresh from the database
    next();
  }

  function deny(req, res, action, target) {
    audit(req.user.id, action, target, 'denied', `role=${req.user.role}`);
    return res.status(403).json({ error: 'Forbidden' });
  }

  // =====================================================================
  // ENROLLMENT AND PASSKEY REGISTRATION (T1)
  // =====================================================================

  // Step 1: prove you are the account holder with the one-time code issued out of band.
  app.post('/enroll/start', enrollLimiter, async (req, res) => {
    const userId = typeof req.body?.userId === 'string' ? req.body.userId.trim().toUpperCase() : '';
    const code = typeof req.body?.code === 'string' ? req.body.code : '';
    const valid = ID_PATTERN.test(userId);
    const user = valid ? q.user.get(userId) : undefined;
    const row = user && q.code.get(userId);
    let reason = null;
    if (!valid) reason = 'malformed account ID';
    else if (!user || !row) reason = 'unknown account or no code';
    else if (row.used_at) reason = 'code already used';
    else if (row.expires_at < Date.now()) reason = 'code expired';
    else if (!timingSafeEqual(Buffer.from(hashCode(code), 'hex'), Buffer.from(row.code_hash, 'hex'))) reason = 'wrong code';
    if (reason) {
      // Not authenticated, so no actor: the target is the account claimed (or "(invalid)", never raw input).
      audit(null, 'enroll.start', valid ? userId : '(invalid)', 'denied', reason);
      return res.status(400).json({ error: 'Invalid or expired enrollment code' });
    }
    await regenerate(req);
    req.session.enroll = { userId, codeHash: row.code_hash, at: Date.now() };
    audit(userId, 'enroll.start', userId, 'allowed');
    res.json({ ok: true, name: user.name });
  });

  function requireEnrollment(req, res, next) {
    const e = req.session.enroll;
    if (!e || Date.now() - e.at > ENROLL_WINDOW_MINUTES * 60 * 1000) {
      return res.status(401).json({ error: 'Enter your account ID and enrollment code first' });
    }
    next();
  }

  // Step 2: one-time registration challenge for the enrolled account only.
  app.get('/webauthn/register/options', requireEnrollment, async (req, res) => {
    const user = q.user.get(req.session.enroll.userId);
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: user.id,
      userDisplayName: user.name,
      userID: Buffer.from(user.webauthn_user_id, 'base64url'),
      attestationType: 'none',
      excludeCredentials: q.passkeysFor.all(user.id).map((p) => ({ id: p.id, transports: JSON.parse(p.transports || '[]') })),
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
    });
    issueChallenge(req, 'register', options.challenge, user.id);
    res.json(options);
  });

  // Step 3: verify the new credential and bind its public key to the enrolled account.
  app.post('/webauthn/register/verify', requireEnrollment, async (req, res) => {
    const { userId, codeHash } = req.session.enroll;    // from the session, never from the request body
    const pending = takeChallenge(req, 'register');     // one-time: gone whatever the outcome
    const expectedChallenge = pending?.userId === userId ? pending.challenge : null;
    if (!expectedChallenge) {
      audit(userId, 'passkey.register', userId, 'denied', 'no pending challenge');
      return res.status(400).json({ verified: false, error: 'No registration in progress' });
    }
    let verification;
    try {
      verification = await verifyRegistrationResponse({
        response: req.body,
        expectedChallenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true,
      });
    } catch (err) {
      audit(userId, 'passkey.register', userId, 'denied', cleanReason(err.message));
      return res.status(400).json({ verified: false, error: 'Registration could not be verified', reason: cleanReason(err.message) });
    }
    if (!verification.verified) {
      audit(userId, 'passkey.register', userId, 'denied', 'not verified');
      return res.status(400).json({ verified: false, error: 'Registration could not be verified' });
    }
    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    db.exec('BEGIN');
    try {
      // The code must still be the one checked at /enroll/start, unused and unexpired.
      if (q.useCode.run(Date.now(), userId, codeHash, Date.now()).changes !== 1) throw new Error('enrollment code no longer valid');
      q.addPasskey.run(credential.id, userId, credential.publicKey, credential.counter,
        JSON.stringify(credential.transports ?? []), credentialDeviceType, credentialBackedUp ? 1 : 0, Date.now());
      db.exec('COMMIT');
    } catch (err) {
      db.exec('ROLLBACK');
      audit(userId, 'passkey.register', userId, 'denied', err.message);
      return res.status(400).json({ verified: false, error: 'Registration could not be completed' });
    }
    delete req.session.enroll;
    audit(userId, 'passkey.register', userId, 'allowed', `credential=${credential.id.slice(0, 8)}...`);
    res.json({ verified: true });
  });

  // =====================================================================
  // PASSKEY SIGN-IN (T2, T3)
  // =====================================================================

  app.post('/webauthn/login/options', loginLimiter, async (req, res) => {
    const userId = typeof req.body?.userId === 'string' ? req.body.userId.trim().toUpperCase() : '';
    const keys = ID_PATTERN.test(userId) ? q.passkeysFor.all(userId) : [];
    if (keys.length === 0) return res.status(400).json({ error: 'No passkey is registered for that account' });
    const options = await generateAuthenticationOptions({
      rpID: RP_ID,
      allowCredentials: keys.map((k) => ({ id: k.id, transports: JSON.parse(k.transports || '[]') })),
      userVerification: 'required',
    });
    issueChallenge(req, 'login', options.challenge, userId);   // fresh challenge per attempt
    res.json(options);
  });

  app.post('/webauthn/login/verify', loginLimiter, async (req, res) => {
    const pending = takeChallenge(req, 'login');        // one-time: a challenge can never be reused
    const fail = (reason) => {
      // Not authenticated, so no actor: the target is the account the challenge was issued for.
      audit(null, 'login', pending?.userId ?? '(none)', 'denied', reason);
      return res.status(400).json({ verified: false, error: 'Sign-in could not be verified', reason });
    };
    if (!pending) return fail('no pending challenge (used, expired or never issued)');
    const key = typeof req.body?.id === 'string' ? q.passkey.get(req.body.id) : undefined;
    if (!key || key.user_id !== pending.userId) return fail('credential not registered to this account');
    let verification;
    try {
      verification = await verifyAuthenticationResponse({
        response: req.body,
        expectedChallenge: pending.challenge,   // freshness: stops replay
        expectedOrigin: ORIGIN,                 // stops phishing origins
        expectedRPID: RP_ID,
        credential: {
          id: key.id,
          publicKey: new Uint8Array(key.public_key),   // signature checked with the stored public key
          counter: key.counter,
          transports: JSON.parse(key.transports || '[]'),
        },
        requireUserVerification: true,          // Touch ID / PIN must have happened
      });
    } catch (err) {
      return fail(cleanReason(err.message));
    }
    if (!verification.verified) return fail('signature not verified');
    q.touchPasskey.run(verification.authenticationInfo.newCounter, Date.now(), key.id);
    await regenerate(req);                              // new session ID at login (stops session fixation)
    req.session.user = { id: pending.userId, credentialId: key.id };
    audit(pending.userId, 'login', pending.userId, 'allowed');
    res.json({ verified: true, redirect: '/app' });
  });

  app.post('/logout', (req, res) => {
    const id = req.session.user?.id;
    req.session.destroy(() => {
      res.clearCookie(SESSION_COOKIE, { path: '/', httpOnly: true, sameSite: 'strict' });
      if (id) audit(id, 'logout', id, 'allowed');
      res.json({ ok: true });
    });
  });

  // =====================================================================
  // PROTECTED API: authentication gate, then authorization policy
  // =====================================================================

  app.get('/me', requireAuth, (req, res) => {
    const courses = req.user.role === 'lecturer' ? q.coursesTaught.all(req.user.id) : [];
    res.json({ ...req.user, courses });
  });

  app.get('/students/:studentId', requireAuth, (req, res) => {
    const { studentId } = req.params;
    if (!validIds([studentId, ID_PATTERN])) return res.status(404).json({ error: 'Not found' });
    if (!policy.canReadStudent(req.user, studentId)) return deny(req, res, 'student.read', studentId);
    const s = q.user.get(studentId);
    if (!s) return res.status(404).json({ error: 'Not found' });
    // A lecturer sees only the courses they teach, not the student's whole record.
    const courses = req.user.role === 'student'
      ? q.studentCourses.all(studentId)
      : q.studentCoursesForLecturer.all(req.user.id, studentId);
    res.json({ student: { id: s.id, name: s.name, programme: s.programme, year: s.year }, courses });
  });

  app.get('/courses/:courseId/roster', requireAuth, (req, res) => {
    const { courseId } = req.params;
    if (!validIds([courseId, COURSE_PATTERN])) return res.status(404).json({ error: 'Not found' });
    if (!policy.canViewRoster(req.user, courseId)) return deny(req, res, 'roster.read', courseId);
    res.json({ courseId, students: q.roster.all(courseId) });
  });

  app.post('/courses/:courseId/grades/:studentId', requireAuth, (req, res) => {
    const { courseId, studentId } = req.params;
    if (!validIds([courseId, COURSE_PATTERN], [studentId, ID_PATTERN])) return res.status(404).json({ error: 'Not found' });
    if (!policy.canEditGrade(req.user, courseId, studentId)) return deny(req, res, 'grade.update', `${courseId}/${studentId}`);
    const grade = req.body?.grade;
    if (typeof grade !== 'string' || !GRADES.includes(grade)) return res.status(400).json({ error: `Grade must be one of ${GRADES.join(', ')}` });
    const previous = q.grade.get(studentId, courseId)?.grade ?? null;
    q.setGrade.run(grade, studentId, courseId);
    audit(req.user.id, 'grade.update', `${courseId}/${studentId}`, 'allowed', `${previous} -> ${grade}`);
    res.json({ ok: true, courseId, studentId, previous, grade });
  });

  // ---------- pages ----------
  app.get('/', (req, res) => res.sendFile(join(ROOT, 'public', 'index.html')));
  app.get('/app', (req, res) => (req.session.user ? res.sendFile(join(ROOT, 'public', 'app.html')) : res.redirect('/')));
  app.get('/vendor/simplewebauthn-browser.js', (req, res) =>
    res.sendFile(join(ROOT, 'node_modules', '@simplewebauthn', 'browser', 'dist', 'bundle', 'index.umd.min.js')));
  app.use(express.static(join(ROOT, 'public'), { index: false }));

  app.use((req, res) => res.status(404).json({ error: 'Not found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
    if (err.status && err.status < 500) return res.status(err.status).json({ error: 'Bad request' });
    log(`ERROR ${req.method} ${req.path}: ${err.message}`);  // message only, never the request
    res.status(500).json({ error: 'Server error' });
  });

  return { app, db, origin: ORIGIN };
}

// Run directly: `npm start`
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.loadEnvFile(); } catch { /* no .env file: defaults apply */ }
  const port = Number(process.env.PORT || DEFAULT_PORT);
  const { app, origin } = createApp({ port, dbPath: process.env.DB_PATH || DEFAULT_DB_PATH });
  app.listen(port, () => console.log(`Student Records Portal running at ${origin}`));
}
