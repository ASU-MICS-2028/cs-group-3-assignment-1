// Rebuilds the database with synthetic (fictional) data and issues one-time enrollment codes.
// Usage: npm run seed            (database: data/portal.db, or DB_PATH from .env)
import { rmSync } from 'node:fs';
import { randomBytes, randomInt } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { openDb } from '../db.js';
import { DEFAULT_DB_PATH, CODE_TTL_HOURS } from '../config.js';
import { hashCode } from '../server.js';

// Readable alphabet without look-alike characters (no 0/O, 1/I/L).
const ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
export function newCode() {
  const chars = Array.from({ length: 12 }, () => ALPHABET[randomInt(ALPHABET.length)]).join(''); // about 59 bits
  return `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`;
}

export function issueCode(db, userId) {
  const code = newCode();
  db.prepare(`INSERT INTO enrollment_codes (user_id, code_hash, expires_at, used_at) VALUES (?, ?, ?, NULL)
              ON CONFLICT(user_id) DO UPDATE SET code_hash = excluded.code_hash, expires_at = excluded.expires_at, used_at = NULL`)
    .run(userId, hashCode(code), Date.now() + CODE_TTL_HOURS * 3600 * 1000);
  return code;
}

export function seed(dbPath = DEFAULT_DB_PATH) {
  for (const suffix of ['', '-wal', '-shm']) rmSync(dbPath + suffix, { force: true });
  const db = openDb(dbPath);
  const wid = () => randomBytes(32).toString('base64url');   // opaque WebAuthn user handle, not the student ID

  const users = [
    ['S001', 'Ama Mensah',      'student',  'BSc Computer Science',   2],
    ['S002', 'Kwame Boateng',   'student',  'BSc Computer Science',   2],
    ['L001', 'Dr. Efua Asante', 'lecturer', null, null],
    ['L002', 'Dr. Kofi Owusu',  'lecturer', null, null],
  ];
  const addUser = db.prepare('INSERT INTO users (id, name, role, programme, year, webauthn_user_id) VALUES (?, ?, ?, ?, ?, ?)');
  for (const u of users) addUser.run(...u, wid());

  db.prepare('INSERT INTO courses (id, title) VALUES (?, ?), (?, ?)')
    .run('C101', 'Introduction to Computing', 'C102', 'Data Structures');
  db.prepare('INSERT INTO lecturer_courses (lecturer_id, course_id) VALUES (?, ?), (?, ?)')
    .run('L001', 'C101', 'L002', 'C102');
  db.prepare('INSERT INTO enrollments (student_id, course_id, grade) VALUES (?, ?, ?), (?, ?, ?), (?, ?, ?)')
    .run('S001', 'C101', 'B+', 'S002', 'C101', 'A', 'S002', 'C102', 'B');

  const codes = Object.fromEntries(users.map(([id]) => [id, issueCode(db, id)]));
  db.close();
  return codes;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try { process.loadEnvFile(); } catch { /* optional */ }
  const path = process.env.DB_PATH || DEFAULT_DB_PATH;
  const codes = seed(path);
  console.log(`Database rebuilt: ${path} (synthetic data only)\n`);
  console.log('One-time enrollment codes (valid 24 hours, single use).');
  console.log('In a real deployment these are handed over in person by the Registrar, never by email:\n');
  for (const [id, code] of Object.entries(codes)) console.log(`  ${id}  ${code}`);
  console.log('\nAccounts: S001, S002 (students); L001 (lecturer, C101); L002 (lecturer, C102)');
}
