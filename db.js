import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id               TEXT PRIMARY KEY,
  name             TEXT NOT NULL,
  role             TEXT NOT NULL CHECK (role IN ('student', 'lecturer')),
  programme        TEXT,
  year             INTEGER,
  webauthn_user_id TEXT NOT NULL UNIQUE
);
-- One-time codes that gate passkey registration. Only a hash is stored.
CREATE TABLE IF NOT EXISTS enrollment_codes (
  user_id    TEXT PRIMARY KEY REFERENCES users(id),
  code_hash  TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER
);
-- Public keys only. The private key never leaves the user's device.
CREATE TABLE IF NOT EXISTS passkeys (
  id           TEXT PRIMARY KEY,           -- credential ID (base64url)
  user_id      TEXT NOT NULL REFERENCES users(id),
  public_key   BLOB NOT NULL,
  counter      INTEGER NOT NULL,
  transports   TEXT,
  device_type  TEXT,
  backed_up    INTEGER,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE TABLE IF NOT EXISTS courses (
  id    TEXT PRIMARY KEY,
  title TEXT NOT NULL
);
-- Authorization table: which lecturer teaches which course.
CREATE TABLE IF NOT EXISTS lecturer_courses (
  lecturer_id TEXT NOT NULL REFERENCES users(id),
  course_id   TEXT NOT NULL REFERENCES courses(id),
  PRIMARY KEY (lecturer_id, course_id)
);
-- Authorization table: which student takes which course, and the grade.
CREATE TABLE IF NOT EXISTS enrollments (
  student_id TEXT NOT NULL REFERENCES users(id),
  course_id  TEXT NOT NULL REFERENCES courses(id),
  grade      TEXT,
  PRIMARY KEY (student_id, course_id)
);
-- Accountability: who did what, allowed or denied. Never holds secrets.
CREATE TABLE IF NOT EXISTS audit_log (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  at       TEXT NOT NULL,
  actor_id TEXT,
  action   TEXT NOT NULL,
  target   TEXT,
  outcome  TEXT NOT NULL,
  detail   TEXT
);
`;

export function openDb(path) {
  mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 3000;');
  db.exec(SCHEMA);
  return db;
}
