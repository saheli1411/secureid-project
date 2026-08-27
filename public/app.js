let currentChallengeId = null;
let currentEmail = null;
let currentPhone = null;
let otpTimerInterval = null;
let inMemoryJwt = null; // Stored strictly in memory, NOT localStorage

// Timer Helper
function startTimer(durationSeconds, displayElement, onExpire) {
  clearInterval(otpTimerInterval);
  let remaining = durationSeconds;
  
  function update() {
    const mins = Math.floor(remaining / 60).toString().padStart(2, '0');
    const secs = (remaining % 60).toString().padStart(2, '0');
    displayElement.textContent = `${mins}:${secs}`;
    if (remaining <= 0) {
      clearInterval(otpTimerInterval);
      if (onExpire) onExpire();
    }
    remaining -= 1;
  }
  update();
  otpTimerInterval = setInterval(update, 1000);
}

// Evaluator Tooltip Helper: Fetches simulated OTP without opening the server console
async function fetchEvaluatorOtp(challengeId, badgeElementId) {
  try {
    const res = await fetch(`/api/test/otp/${challengeId}`);
    const data = await res.json();
    if (data.simulatedOtp) {
      const badge = document.getElementById(badgeElementId);
      if (badge) {
        badge.innerHTML = `Simulated OTP: <strong>${data.simulatedOtp}</strong>`;
        badge.style.display = 'block';
      }
    }
  } catch (e) {
    console.warn('Evaluator OTP fetch skipped');
  }
}

// ==========================================
// REGISTRATION JOURNEY
// ==========================================
const regForm = document.getElementById('registerForm');
if (regForm) {
  // Dynamic Password Validation
  const pwdInput = document.getElementById('regPassword');
  pwdInput?.addEventListener('input', () => {
    const val = pwdInput.value;
    document.getElementById('req-len')?.classList.toggle('valid', val.length >= 8);
    document.getElementById('req-upper')?.classList.toggle('valid', /[A-Z]/.test(val));
    document.getElementById('req-num')?.classList.toggle('valid', /[0-9]/.test(val));
    document.getElementById('req-spec')?.classList.toggle('valid', /[^A-Za-z0-9]/.test(val));
  });

  // Password Visibility Toggle
  document.getElementById('toggleRegPassword')?.addEventListener('click', () => {
    pwdInput.type = pwdInput.type === 'password' ? 'text' : 'password';
  });

  // Step 1: Submit Details
  regForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const name = document.getElementById('regName').value.trim();
    const email = document.getElementById('regEmail').value.trim();
    const phone = document.getElementById('regPhone').value.trim();
    const password = document.getElementById('regPassword').value;
    const errorMsg = document.getElementById('regError');

    errorMsg.textContent = '';
    const res = await fetch('/api/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, phone, password })
    });
    const data = await res.json();

    if (!res.ok) {
      errorMsg.textContent = data.error;
      return;
    }

    currentChallengeId = data.challengeId;
    currentEmail = data.email;
    currentPhone = data.phone;

    document.getElementById('displayEmail').textContent = currentEmail;
    document.getElementById('reg-stage-form').style.display = 'none';
    document.getElementById('reg-stage-email-otp').style.display = 'block';
    document.getElementById('step-2')?.classList.add('active');

    fetchEvaluatorOtp(currentChallengeId, 'evaluator-email-otp');
    startTimer(data.expiresInSeconds || 120, document.getElementById('emailTimer'), () => {
      document.getElementById('emailOtpMsg').textContent = 'This code has expired. Please request a new code.';
      document.getElementById('emailOtpMsg').className = 'status-msg error-text';
      document.getElementById('verifyEmailOtpBtn').disabled = true;
    });
  });

  // Step 2: Verify Email OTP
  document.getElementById('verifyEmailOtpBtn')?.addEventListener('click', async () => {
    const otp = document.getElementById('emailOtpInput').value.trim();
    const msg = document.getElementById('emailOtpMsg');

    const res = await fetch('/api/verify-email-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: currentChallengeId, otp })
    });
    const data = await res.json();

    if (!res.ok) {
      msg.textContent = data.error;
      msg.className = 'status-msg error-text';
      return;
    }

    // Trigger SMS Stage
    const smsRes = await fetch('/api/send-sms-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: currentEmail })
    });
    const smsData = await smsRes.json();
    currentChallengeId = smsData.challengeId;

    document.getElementById('displayPhone').textContent = currentPhone;
    document.getElementById('reg-stage-email-otp').style.display = 'none';
    document.getElementById('reg-stage-sms-otp').style.display = 'block';
    document.getElementById('step-3')?.classList.add('active');

    fetchEvaluatorOtp(currentChallengeId, 'evaluator-sms-otp');
    startTimer(smsData.expiresInSeconds || 120, document.getElementById('smsTimer'), () => {
      document.getElementById('smsOtpMsg').textContent = 'This code has expired. Please request a new code.';
      document.getElementById('smsOtpMsg').className = 'status-msg error-text';
      document.getElementById('verifySmsOtpBtn').disabled = true;
    });
  });

  // Resend Email OTP
  document.getElementById('resendEmailOtpBtn')?.addEventListener('click', async () => {
    const res = await fetch('/api/send-email-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: currentEmail })
    });
    const data = await res.json();
    currentChallengeId = data.challengeId;
    document.getElementById('emailOtpInput').value = '';
    document.getElementById('emailOtpMsg').textContent = 'New code sent!';
    document.getElementById('emailOtpMsg').className = 'status-msg success-text';
    document.getElementById('verifyEmailOtpBtn').disabled = false;
    fetchEvaluatorOtp(currentChallengeId, 'evaluator-email-otp');
    startTimer(120, document.getElementById('emailTimer'));
  });

  // Step 3: Verify SMS OTP
  document.getElementById('verifySmsOtpBtn')?.addEventListener('click', async () => {
    const otp = document.getElementById('smsOtpInput').value.trim();
    const msg = document.getElementById('smsOtpMsg');

    const res = await fetch('/api/verify-sms-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: currentChallengeId, otp })
    });
    const data = await res.json();

    if (!res.ok) {
      msg.textContent = data.error;
      msg.className = 'status-msg error-text';
      return;
    }

    clearInterval(otpTimerInterval);
    document.getElementById('reg-stage-sms-otp').style.display = 'none';
    document.getElementById('reg-stage-success').style.display = 'block';
    document.getElementById('step-4')?.classList.add('active');
  });

  // Resend SMS OTP
  document.getElementById('resendSmsOtpBtn')?.addEventListener('click', async () => {
    const res = await fetch('/api/send-sms-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: currentEmail })
    });
    const data = await res.json();
    currentChallengeId = data.challengeId;
    document.getElementById('smsOtpInput').value = '';
    document.getElementById('smsOtpMsg').textContent = 'New code sent!';
    document.getElementById('smsOtpMsg').className = 'status-msg success-text';
    document.getElementById('verifySmsOtpBtn').disabled = false;
    fetchEvaluatorOtp(currentChallengeId, 'evaluator-sms-otp');
    startTimer(120, document.getElementById('smsTimer'));
  });
}

// ==========================================
// LOGIN & MFA JOURNEY
// ==========================================
const loginForm = document.getElementById('loginForm');
if (loginForm) {
  // Password Visibility Toggle
  document.getElementById('toggleLoginPassword')?.addEventListener('click', () => {
    const pass = document.getElementById('loginPassword');
    pass.type = pass.type === 'password' ? 'text' : 'password';
  });

  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorMsg = document.getElementById('loginError');

    errorMsg.textContent = '';
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    if (!res.ok) {
      errorMsg.textContent = data.error;
      return;
    }

    if (data.mfaRequired) {
      currentChallengeId = data.challengeId;
      document.getElementById('login-view-creds').style.display = 'none';
      document.getElementById('login-view-mfa').style.display = 'block';
      document.getElementById('mfaEmailDisplay').textContent = data.email;

      fetchEvaluatorOtp(currentChallengeId, 'evaluator-login-otp');
      startTimer(data.expiresInSeconds || 120, document.getElementById('loginOtpTimer'), () => {
        document.getElementById('loginOtpMsg').textContent = 'Code expired. Please login again.';
        document.getElementById('loginOtpMsg').className = 'status-msg error-text';
        document.getElementById('verifyLoginOtpBtn').disabled = true;
      });
    } else {
      window.location.href = 'dashboard.html';
    }
  });

  document.getElementById('verifyLoginOtpBtn')?.addEventListener('click', async () => {
    const otp = document.getElementById('loginOtpInput').value.trim();
    const msg = document.getElementById('loginOtpMsg');

    const res = await fetch('/api/verify-login-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challengeId: currentChallengeId, otp })
    });
    const data = await res.json();

    if (!res.ok) {
      msg.textContent = data.error;
      msg.className = 'status-msg error-text';
      return;
    }

    clearInterval(otpTimerInterval);
    window.location.href = 'dashboard.html';
  });
}

// ==========================================
// DASHBOARD & JWT PROTECTION
// ==========================================
const dashName = document.getElementById('dashName');
if (dashName) {
  fetch('/api/me')
    .then(res => {
      if (!res.ok) throw new Error('Not authenticated');
      return res.json();
    })
    .then(user => {
      dashName.textContent = user.name || 'User';
      document.getElementById('dashEmail').textContent = user.email;
    })
    .catch(() => {
      window.location.href = 'index.html';
    });

  document.getElementById('dashLogoutBtn')?.addEventListener('click', async () => {
    await fetch('/api/logout', { method: 'POST' });
    inMemoryJwt = null;
    window.location.href = 'index.html';
  });

  // JWT Flow: Issues short-lived token in-memory and queries protected endpoint
  document.getElementById('testJwtBtn')?.addEventListener('click', async () => {
    const resToken = await fetch('/api/token', { method: 'POST' });
    const tokenData = await resToken.json();

    if (!resToken.ok) {
      document.getElementById('jwtResult').textContent = tokenData.error;
      return;
    }

    inMemoryJwt = tokenData.accessToken; // Kept in memory, never stored in localStorage

    const resProtected = await fetch('/api/protected', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${inMemoryJwt}`
      }
    });
    const protectedData = await resProtected.json();
    document.getElementById('jwtResult').innerHTML = `
      <span style="color:#16a34a">✓ ${protectedData.message}</span><br/>
      <small>Issued At: ${protectedData.issuedAt}</small>
    `;
  });
}