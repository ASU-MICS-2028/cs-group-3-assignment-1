const { startRegistration, startAuthentication, browserSupportsWebAuthn } = SimpleWebAuthnBrowser;
const $ = (id) => document.getElementById(id);
const status = (text, kind = '') => { $('status').textContent = text; $('status').className = kind; };

async function postJSON(url, body) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return { status: r.status, ok: r.ok, data: await r.json().catch(() => ({})) };
}

if (!browserSupportsWebAuthn()) status('This browser cannot use passkeys. Open the portal in a current version of Chrome or Safari.', 'error');

// Sign in: the server issues a fresh challenge, this device signs it, the server verifies the signature.
$('signin-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  status('Waiting for your passkey…');
  try {
    const opts = await postJSON('/webauthn/login/options', { userId: $('signin-id').value });
    if (!opts.ok) return status(`${opts.data.error}. Check the account ID, or set up a passkey below.`, 'error');
    const assertion = await startAuthentication({ optionsJSON: opts.data });
    const r = await postJSON('/webauthn/login/verify', assertion);
    if (!r.ok || !r.data.verified) return status(`Sign-in failed: the server could not verify this passkey (${r.data.reason}). You are not signed in.`, 'error');
    window.location.assign(r.data.redirect);
  } catch (err) {
    status(`Sign-in stopped before it finished: ${err.message}`, 'error');
  }
});

// First-time setup, step 1: the one-time code proves who is registering.
$('enroll-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const r = await postJSON('/enroll/start', { userId: $('enroll-id').value, code: $('enroll-code').value });
  if (!r.ok) return status(`${r.data.error}. Ask the Registrar for a new code if this one has been used.`, 'error');
  $('register-hello').textContent = `Code accepted for ${r.data.name}. Create a passkey on this device to finish.`;
  $('register-step').hidden = false;
  status('');
});

// Step 2: create the passkey. The private key stays on this device; only the public key is sent.
$('register-passkey').addEventListener('click', async () => {
  try {
    const opts = await fetch('/webauthn/register/options');
    if (!opts.ok) return status('Setup expired. Enter your account ID and code again.', 'error');
    const attestation = await startRegistration({ optionsJSON: await opts.json() });
    const r = await postJSON('/webauthn/register/verify', attestation);
    if (!r.ok || !r.data.verified) return status(`Passkey not saved: ${r.data.reason || r.data.error}.`, 'error');
    const id = $('enroll-id').value.trim().toUpperCase();
    $('register-step').hidden = true;
    $('enroll-form').reset();
    $('signin-id').value = id;
    status(`Passkey saved for ${id}. You can sign in now.`, 'ok');
  } catch (err) {
    status(`Passkey setup stopped before it finished: ${err.message}`, 'error');
  }
});
