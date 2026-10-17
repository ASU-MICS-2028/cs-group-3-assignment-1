Run 2026-10-17T14:52:04.583Z on http://localhost:3000, Node v22.22.0

| Test | Identity | Request / action | Expected | Observed | HTTP | Result |
| --- | --- | --- | --- | --- | --- | --- |
| T1 | S001 | Enroll with one-time code, then register a passkey | Credential stored for S001; public key server-side | 200 verified; passkeys row: user_id=S001, credential K3CiY8VECT..., public key 42 bytes | 200 | Pass |
| T2 | S001 | Sign in with the registered passkey | Fresh challenge verified; session created | 200 verified; GET /me -> 200 {"id":"S001","role":"student","name":"Ama Mensah","courses":[]} | 200 | Pass |
| T3a | S001 | Log out, get a fresh challenge, resend the captured T2 sign-in response | Rejected; no session | 400 Unexpected authentication response challenge "...", expected "..."; GET /me -> 401 | 400 | Pass |
| T3b | S001 | Change one character of the signature in a live sign-in response | Rejected; no session | 400 signature not verified; GET /me -> 401 | 400 | Pass |
| T4 | none | GET /students/S001 with no session (fresh browser profile) | Denied (401) | 401 {"error":"Not signed in"} | 401 | Pass |
| T5 | S001 | GET /students/S001 (own record) | Allowed (200) | 200 {"student":{"id":"S001","name":"Ama Mensah","programme":"BSc Computer Science","year":2},"... | 200 | Pass |
| T6 | S001 | GET /students/S002 by editing the URL, then by fetch() | Denied by server (403) | URL 403; fetch 403 {"error":"Forbidden"} | 403 | Pass |
| T7 | S001 | POST /courses/C101/grades/S002 by fetch() (body claims role=lecturer) | Denied (403); grade unchanged | 403 {"error":"Forbidden"}; S002 C101 grade A before, A after | 403 | Pass |
| T8 | L001 | Change S001's C101 grade in the UI and save | Allowed (200); lecturer-course link verified | 200; S001 C101 grade B+ -> A; audit line written | 200 | Pass |
| X1 | L001 | POST /courses/C102/grades/S002 (a course L001 does not teach) | Denied (403) | 403 {"error":"Forbidden"}; S002 C102 grade still B | 403 | Pass |
| X2 | L001 | GET /students/S002 (S002 takes C101 and C102) | Allowed, but only the C101 part | 200; courses returned: C101 | 200 | Pass |
| X3 | any | Reuse S001's enrollment code after T1 | Rejected (single use) | 400 {"error":"Invalid or expired enrollment code"} | 400 | Pass |
| X4 | none | GET /webauthn/register/options without enrolling | Denied (401) | 401 {"error":"Enter your account ID and enrollment code first"} | 401 | Pass |
| X5 | S001 | Log out, then GET /students/S001 | Denied (401) | 401 {"error":"Not signed in"} | 401 | Pass |
| X7 | S001 | Send one valid sign-in response twice in parallel | Exactly one succeeds | statuses 200 and 400 | 200/400 | Pass |
| X6 | L001 | Registrar removes L001 from C101; L001 (still signed in) retries a C101 grade change | Denied on the very next request | 403 {"error":"Forbidden"}; GET /students/S001 -> 403; grade still A | 403 | Pass |
