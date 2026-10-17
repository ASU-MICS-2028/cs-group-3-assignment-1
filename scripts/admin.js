// Registrar / IT console actions. Deliberately NOT web routes: no user of the portal
// (not even a lecturer) can administer accounts through the application.
//   npm run admin -- unassign L001 C101     end a lecturer's access to a course
//   npm run admin -- issue-code S001        issue a fresh enrollment code (passkey recovery)
//   npm run admin -- revoke-passkeys S001   revoke all of a user's passkeys (ends their sessions)
import { fileURLToPath } from 'node:url';
import { openDb } from '../db.js';
import { DEFAULT_DB_PATH } from '../config.js';
import { issueCode } from './seed.js';

const audit = (db, action, target, detail) => db.prepare(
  'INSERT INTO audit_log (at, actor_id, action, target, outcome, detail) VALUES (?, ?, ?, ?, ?, ?)')
  .run(new Date().toISOString(), 'registrar-console', action, target, 'allowed', detail);

export function unassign(db, lecturerId, courseId) {
  const n = db.prepare('DELETE FROM lecturer_courses WHERE lecturer_id = ? AND course_id = ?').run(lecturerId, courseId).changes;
  audit(db, 'course.unassign', `${lecturerId}/${courseId}`, `${n} row removed`);
  return n;
}
export function revokePasskeys(db, userId) {
  const n = db.prepare('DELETE FROM passkeys WHERE user_id = ?').run(userId).changes;
  audit(db, 'passkey.revoke', userId, `${n} passkey(s) removed`);
  return n;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.loadEnvFile(); } catch { /* optional */ }
  const db = openDb(process.env.DB_PATH || DEFAULT_DB_PATH);
  const [cmd, a, b] = process.argv.slice(2);
  if (cmd === 'unassign' && a && b) console.log(`Removed ${unassign(db, a, b)} assignment(s): ${a} no longer teaches ${b}.`);
  else if (cmd === 'issue-code' && a) { const c = issueCode(db, a); audit(db, 'code.issue', a, 'new enrollment code'); console.log(`New enrollment code for ${a}: ${c}`); }
  else if (cmd === 'revoke-passkeys' && a) console.log(`Revoked ${revokePasskeys(db, a)} passkey(s) for ${a}.`);
  else { console.log('Usage: npm run admin -- unassign <lecturer> <course> | issue-code <user> | revoke-passkeys <user>'); process.exitCode = 1; }
  db.close();
}
