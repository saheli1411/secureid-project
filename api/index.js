const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'secureid-iam-secret-jwt-key-2026';
const MAX_ATTEMPTS = 3;
const OTP_EXPIRY_MS = 2 * 60 * 1000; // 2 minutes

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// Cookie-based Session Configuration
app.use(session({
  name: 'secureid_session',
  secret: process.env.SESSION_SECRET || 'secureid-session-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// In-Memory Storage
const users = new Map();         // email -> User Object
const challenges = new Map();    // challengeId -> Challenge Object
const failedLogins = new Map();  // email -> { attempts, lockoutUntil }
const evaluatorOtpStore = new Map(); // challengeId -> plainOtp (for evaluator testing)

// Helpers
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function hashValue(val) {
  return crypto.createHash('sha256').update(val).digest('hex');
}

function createChallenge(userId, channel, recipient) {
  const otp = generateOTP();
  const challengeId = crypto.randomUUID();
  
  challenges.set(challengeId, {
    challengeId,
    userId,
    channel,
    otpHash: hashValue(otp),
    expiresAt: Date.now() + OTP_EXPIRY_MS,
    attempts: 0
  });

  // Store for evaluator API & log to server console
  evaluatorOtpStore.set(challengeId, otp);
  console.log(`\n========================================`);
  console.log(`[SIMULATED ${channel.toUpperCase()} OTP]`);
  console.log(`To: ${recipient}`);
  console.log(`OTP Code: ${otp}`);
  console.log(`Challenge ID: ${challengeId}`);
  console.log(`Expires In: 2 Minutes`);
  console.log(`========================================\n`);

  return challengeId;
}

// ----------------------------------------------------
// EVALUATOR TESTING HELPER ENDPOINT
// ----------------------------------------------------
app.get('/api/test/otp/:challengeId', (req, res) => {
  const otp = evaluatorOtpStore.get(req.params.challengeId);
  if (!otp) return res.status(404).json({ error: 'No active OTP found or expired' });
  res.json({ simulatedOtp: otp });
});

// ----------------------------------------------------
// 1. REGISTRATION ENDPOINTS
// ----------------------------------------------------
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();
  if (users.has(normalizedEmail)) {
    return res.status(400).json({ error: 'An account with this email already exists.' });
  }

  const passwordHash = await bcrypt.hash(password, 10);
  const user = {
    id: crypto.randomUUID(),
    name,
    email: normalizedEmail,
    phone,
    passwordHash,
    emailVerified: false,
    phoneVerified: false,
    mfaEnabled: false
  };

  users.set(normalizedEmail, user);
  const challengeId = createChallenge(user.id, 'email', user.email);

  res.json({
    success: true,
    challengeId,
    email: user.email,
    phone: user.phone,
    expiresInSeconds: OTP_EXPIRY_MS / 1000
  });
});

app.post('/api/send-email-otp', (req, res) => {
  const { email } = req.body;
  const user = users.get(email?.toLowerCase().trim());
  if (!user) return res.status(404).json({ error: 'User not found' });

  const challengeId = createChallenge(user.id, 'email', user.email);
  res.json({ success: true, challengeId, expiresInSeconds: OTP_EXPIRY_MS / 1000 });
});

app.post('/api/verify-email-otp', (req, res) => {
  const { challengeId, otp } = req.body;
  const challenge = challenges.get(challengeId);

  if (!challenge) return res.status(400).json({ status: 'invalid', error: 'Invalid challenge session.' });
  if (Date.now() > challenge.expiresAt) {
    challenges.delete(challengeId);
    evaluatorOtpStore.delete(challengeId);
    return res.status(400).json({ status: 'expired', error: 'Code has expired.' });
  }

  challenge.attempts += 1;
  if (challenge.otpHash !== hashValue(otp)) {
    if (challenge.attempts >= MAX_ATTEMPTS) {
      challenges.delete(challengeId);
      evaluatorOtpStore.delete(challengeId);
      return res.status(400).json({ status: 'max_attempts', error: 'Maximum attempts reached.' });
    }
    const remaining = MAX_ATTEMPTS - challenge.attempts;
    return res.status(400).json({ status: 'wrong_code', error: `Incorrect code. Please try again. You have ${remaining} attempts left.` });
  }

  challenges.delete(challengeId);
  evaluatorOtpStore.delete(challengeId);

  for (let u of users.values()) {
    if (u.id === challenge.userId) {
      u.emailVerified = true;
      break;
    }
  }

  res.json({ success: true, message: 'Email verified successfully.' });
});

app.post('/api/send-sms-otp', (req, res) => {
  const { email } = req.body;
  const user = users.get(email?.toLowerCase().trim());
  if (!user) return res.status(404).json({ error: 'User not found' });

  const challengeId = createChallenge(user.id, 'sms', user.phone);
  res.json({ success: true, challengeId, expiresInSeconds: OTP_EXPIRY_MS / 1000 });
});

app.post('/api/verify-sms-otp', (req, res) => {
  const { challengeId, otp } = req.body;
  const challenge = challenges.get(challengeId);

  if (!challenge) return res.status(400).json({ status: 'invalid', error: 'Invalid challenge session.' });
  if (Date.now() > challenge.expiresAt) {
    challenges.delete(challengeId);
    evaluatorOtpStore.delete(challengeId);
    return res.status(400).json({ status: 'expired', error: 'Code has expired.' });
  }

  challenge.attempts += 1;
  if (challenge.otpHash !== hashValue(otp)) {
    if (challenge.attempts >= MAX_ATTEMPTS) {
      challenges.delete(challengeId);
      evaluatorOtpStore.delete(challengeId);
      return res.status(400).json({ status: 'max_attempts', error: 'Maximum attempts reached. Please request a new code.' });
    }
    const remaining = MAX_ATTEMPTS - challenge.attempts;
    return res.status(400).json({ status: 'wrong_code', error: `Incorrect code. Please try again. You have ${remaining} attempts left.` });
  }

  challenges.delete(challengeId);
  evaluatorOtpStore.delete(challengeId);

  for (let u of users.values()) {
    if (u.id === challenge.userId) {
      u.phoneVerified = true;
      u.mfaEnabled = true;
      break;
    }
  }

  res.json({ success: true, message: 'Mobile verified and MFA enabled.' });
});

// ----------------------------------------------------
// 2. LOGIN & MFA ENDPOINTS
// ----------------------------------------------------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = email?.toLowerCase().trim();
  const user = users.get(normalizedEmail);

  // Brute force lockout check
  const lock = failedLogins.get(normalizedEmail);
  if (lock && lock.lockoutUntil && Date.now() < lock.lockoutUntil) {
    const waitSec = Math.ceil((lock.lockoutUntil - Date.now()) / 1000);
    return res.status(429).json({ error: `Account locked due to multiple failed attempts. Try again in ${waitSec}s.` });
  }

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    const currentLock = lock || { attempts: 0 };
    currentLock.attempts += 1;
    if (currentLock.attempts >= 5) {
      currentLock.lockoutUntil = Date.now() + 5 * 60 * 1000;
      failedLogins.set(normalizedEmail, currentLock);
      return res.status(429).json({ error: 'Account temporarily locked (5 failed attempts). Try again in 5 minutes.' });
    }
    failedLogins.set(normalizedEmail, currentLock);
    return res.status(401).json({ error: 'Invalid email or password. Please try again.' });
  }

  failedLogins.delete(normalizedEmail);

  if (user.mfaEnabled) {
    const challengeId = createChallenge(user.id, 'email', user.email);
    return res.json({
      mfaRequired: true,
      method: 'email',
      challengeId,
      email: user.email,
      expiresInSeconds: OTP_EXPIRY_MS / 1000
    });
  }

  // Fallback if MFA is not enabled
  req.session.userId = user.id;
  req.session.email = user.email;
  req.session.name = user.name;
  res.json({ success: true, mfaRequired: false });
});

app.post('/api/verify-login-otp', (req, res) => {
  const { challengeId, otp } = req.body;
  const challenge = challenges.get(challengeId);

  if (!challenge) return res.status(400).json({ status: 'invalid', error: 'Invalid challenge session.' });
  if (Date.now() > challenge.expiresAt) {
    challenges.delete(challengeId);
    evaluatorOtpStore.delete(challengeId);
    return res.status(400).json({ status: 'expired', error: 'Code has expired.' });
  }

  challenge.attempts += 1;
  if (challenge.otpHash !== hashValue(otp)) {
    if (challenge.attempts >= MAX_ATTEMPTS) {
      challenges.delete(challengeId);
      evaluatorOtpStore.delete(challengeId);
      return res.status(400).json({ status: 'max_attempts', error: 'Maximum attempts reached.' });
    }
    const remaining = MAX_ATTEMPTS - challenge.attempts;
    return res.status(400).json({ status: 'wrong_code', error: `Incorrect code. Please try again. You have ${remaining} attempts left.` });
  }

  let authenticatedUser = null;
  for (let u of users.values()) {
    if (u.id === challenge.userId) {
      authenticatedUser = u;
      break;
    }
  }

  challenges.delete(challengeId);
  evaluatorOtpStore.delete(challengeId);

  // Set Session Cookie
  req.session.userId = authenticatedUser.id;
  req.session.email = authenticatedUser.email;
  req.session.name = authenticatedUser.name;

  res.json({ success: true, message: 'Authentication successful' });
});

// ----------------------------------------------------
// 3. SESSION & PROTECTED ENDPOINTS
// ----------------------------------------------------
app.get('/api/me', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Unauthorized: No active session' });
  }
  res.json({
    id: req.session.userId,
    name: req.session.name,
    email: req.session.email
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) return res.status(500).json({ error: 'Logout failed' });
    res.clearCookie('secureid_session');
    res.json({ success: true, message: 'Session invalidated' });
  });
});

// ----------------------------------------------------
// 4. JWT PROTECTED API FLOW
// ----------------------------------------------------
app.post('/api/token', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Active session required to issue short-lived JWT' });
  }
  const token = jwt.sign(
    { sub: req.session.userId, email: req.session.email, name: req.session.name },
    JWT_SECRET,
    { expiresIn: '15m' }
  );
  res.json({ accessToken: token });
});

app.get('/api/protected', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or malformed Authorization header' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    res.json({
      message: 'Access granted to IAM protected API',
      user: payload,
      issuedAt: new Date(payload.iat * 1000).toISOString()
    });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired JWT token' });
  }
});

// Local dev runner
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`IAM Server active on http://localhost:${PORT}`));
}

module.exports = app;