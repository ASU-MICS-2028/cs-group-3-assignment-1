// Relying-party (RP) settings. WebAuthn binds every passkey to the RP ID,
// and the server rejects any response whose origin or RP ID does not match.
export const RP_NAME = 'Student Records Portal (ICS570 Lab 2)';
export const RP_ID = 'localhost'; // must be a domain name, so 'localhost', never '127.0.0.1'
export const DEFAULT_PORT = Number(process.env.PORT || 3000);
export const originFor = (port) => `http://localhost:${port}`;

export const IDLE_MINUTES = 15;          // session ends after 15 minutes without a request
export const ENROLL_WINDOW_MINUTES = 10; // time allowed between entering a code and creating the passkey
export const CODE_TTL_HOURS = 24;        // enrollment codes expire after 24 hours

export const GRADES = ['A+', 'A', 'B+', 'B', 'C+', 'C', 'D+', 'D', 'E'];
export const DEFAULT_DB_PATH = process.env.DB_PATH || 'data/portal.db';
