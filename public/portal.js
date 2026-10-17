// The page only offers what this user is allowed to do. That is convenience, not security:
// the server checks every request again in policy.js.
const $ = (id) => document.getElementById(id);
const el = (tag, props = {}, ...children) => { const n = Object.assign(document.createElement(tag), props); n.append(...children); return n; };
const GRADES = ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'E'];

async function getJSON(url) {
  const r = await fetch(url);
  if (r.status === 401) { window.location.assign('/'); throw new Error('signed out'); }
  return { status: r.status, ok: r.ok, data: await r.json().catch(() => ({})) };
}

function table(headers, rows, numericCols = []) {
  const cell = (tag, i, content) => el(tag, numericCols.includes(i) ? { className: tag === 'td' ? 'num grade' : 'num' } : {}, content);
  return el('table', {},
    el('thead', {}, el('tr', {}, ...headers.map((h, i) => cell('th', i, h)))),
    el('tbody', {}, ...rows.map((cells) => el('tr', {}, ...cells.map((c, i) => cell('td', i, c))))));
}

async function showStudent(me) {
  const { data } = await getJSON(`/students/${encodeURIComponent(me.id)}`);
  const s = data.student;
  const facts = el('dl', { className: 'facts' },
    ...[['Student ID', s.id], ['Programme', s.programme], ['Year', String(s.year)]]
      .map(([k, v]) => el('div', {}, el('dt', { textContent: k }), el('dd', { textContent: v }))));
  $('content').append(el('article', { className: 'sheet', id: 'record' },
    el('h1', { textContent: s.name }), facts,
    table(['Course', 'Title', 'Grade'], data.courses.map((c) => [c.courseId, c.title, c.grade ?? '–']), [2]),
    el('p', { className: 'note', textContent: 'Only you and the lecturers of your courses can see this record.' })));
}

async function showLecturer(me) {
  $('content').append(el('h1', { textContent: 'Your courses' }));
  if (me.courses.length === 0) {
    $('content').append(el('p', { className: 'lede', textContent: 'You are not assigned to any course. Ask the Registrar if this is wrong.' }));
    return;
  }
  for (const course of me.courses) {
    const { data } = await getJSON(`/courses/${encodeURIComponent(course.id)}/roster`);
    const rows = data.students.map((st) => {
      const select = el('select', { ariaLabel: `Grade for ${st.name}` },
        ...GRADES.map((g) => el('option', { value: g, textContent: g, selected: g === st.grade })));
      select.dataset.student = st.studentId; select.dataset.course = course.id;
      const note = el('span', { className: 'row-status', role: 'status' });
      note.dataset.rowStatus = `${course.id}:${st.studentId}`;
      const save = el('button', { type: 'button', className: 'quiet', textContent: 'Save grade' });
      save.dataset.save = `${course.id}:${st.studentId}`;
      save.addEventListener('click', async () => {
        const r = await fetch(`/courses/${course.id}/grades/${st.studentId}`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ grade: select.value }) });
        const body = await r.json().catch(() => ({}));
        note.textContent = r.ok ? `Saved: ${body.previous} to ${body.grade}` : `Not saved: ${body.error}`;
        note.className = `row-status ${r.ok ? 'ok' : 'error'}`;
      });
      return [st.studentId, st.name, select, el('span', {}, save, ' ', note)];
    });
    $('content').append(el('section', { className: 'sheet', id: `roster-${course.id}` },
      el('h2', { textContent: `${course.id} ${course.title}` }),
      table(['Student ID', 'Name', 'Grade', ''], rows)));
  }
}

$('logout').addEventListener('click', async () => {
  await fetch('/logout', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
  window.location.assign('/');
});

(async () => {
  const { data: me } = await getJSON('/me');
  $('whoami').append(el('strong', { textContent: me.name }), ` (${me.id}, ${me.role})`);
  if (me.role === 'student') await showStudent(me); else await showLecturer(me);
})().catch((e) => {
  if (e.message !== 'signed out') $('content').append(el('p', { className: 'row-status error', textContent: `Could not load your page: ${e.message}` }));
});
