const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'secureid-iam-secret-jwt-key-2026';
const SESSION_SECRET = 'secureid-session-cookie-secret-2026';
const HMAC_SECRET = 'challenge-signing-secret-2026';
const OTP_EXPIRY_MS = 2 * 60 * 1000;

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../public')));

// Stateless Session Helper
function setSessionCookie(res, user) {
  const token = jwt.sign(
    { userId: user.id, name: user.name, email: user.email },
    SESSION_SECRET,
    { expiresIn: '1d' }
  );
  res.cookie('secureid_session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  });
}

function getSessionUser(req) {
  const token = req.cookies.secureid_session;
  if (!token) return null;
  try {
    return jwt.verify(token, SESSION_SECRET);
  } catch (err) {
    return null;
  }
}

// Helpers for Challenge Signatures
function hashValue(val) {
  return crypto.createHash('sha256').update(val).digest('hex');
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function issueChallengePayload(userId, channel, recipient, attempts = 0, forcedOtp = null) {
  const otp = forcedOtp || generateOTP();
  const challengeId = crypto.randomUUID();
  const expiresAt = Date.now() + OTP_EXPIRY_MS;
  const otpHash = hashValue(otp);

  const payload = { challengeId, userId, channel, recipient, otpHash, expiresAt, attempts, otp };
  const payloadStr = JSON.stringify(payload);
  const signature = crypto.createHmac('sha256', HMAC_SECRET).update(payloadStr).digest('hex');
  const challengeToken = Buffer.from(payloadStr).toString('base64') + '.' + signature;

  return { challengeToken, challengeId, otp, expiresInSeconds: 120 };
}

function verifyChallengeToken(token) {
  if (!token || !token.includes('.')) return null;
  const [b64, signature] = token.split('.');
  const payloadStr = Buffer.from(b64, 'base64').toString('utf8');
  const expectedSig = crypto.createHmac('sha256', HMAC_SECRET).update(payloadStr).digest('hex');

  if (signature !== expectedSig) return null;
  try {
    return JSON.parse(payloadStr);
  } catch (e) {
    return null;
  }
}

// ----------------------------------------------------
// 1. REGISTRATION ENDPOINTS
// ----------------------------------------------------
app.post('/api/register', async (req, res) => {
  const { name, email, phone, password } = req.body;
  if (!name || !email || !phone || !password) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  const normalizedEmail = email.toLowerCase().trim();
  const userId = crypto.randomUUID();
  const challenge = issueChallengePayload(userId, 'email', normalizedEmail);

  res.json({
    success: true,
    challengeToken: challenge.challengeToken,
    challengeId: challenge.challengeId,
    simulatedOtp: challenge.otp,
    email: normalizedEmail,
    phone,
    name,
    expiresInSeconds: challenge.expiresInSeconds
  });
});

app.post('/api/send-email-otp', (req, res) => {
  const { email } = req.body;
  const challenge = issueChallengePayload(crypto.randomUUID(), 'email', email?.toLowerCase().trim());
  res.json({
    success: true,
    challengeToken: challenge.challengeToken,
    simulatedOtp: challenge.otp,
    expiresInSeconds: challenge.expiresInSeconds
  });
});

app.post('/api/verify-email-otp', (req, res) => {
  const { challengeToken, otp } = req.body;
  const payload = verifyChallengeToken(challengeToken);

  if (!payload) return res.status(400).json({ status: 'invalid', error: 'Invalid challenge session.' });
  if (Date.now() > payload.expiresAt) return res.status(400).json({ status: 'expired', error: 'Code has expired.' });

  if (payload.otpHash !== hashValue(otp)) {
    const attempts = payload.attempts + 1;
    if (attempts >= 3) {
      return res.status(400).json({ status: 'max_attempts', error: 'Maximum attempts reached.' });
    }
    const updated = issueChallengePayload(payload.userId, payload.channel, payload.recipient, attempts, payload.otp);
    return res.status(400).json({
      status: 'wrong_code',
      error: `Incorrect code. ${3 - attempts} attempt(s) left.`,
      updatedToken: updated.challengeToken
    });
  }

  res.json({ success: true, message: 'Email verified successfully.' });
});

app.post('/api/send-sms-otp', (req, res) => {
  const { phone } = req.body;
  const challenge = issueChallengePayload(crypto.randomUUID(), 'sms', phone || 'mobile');
  res.json({
    success: true,
    challengeToken: challenge.challengeToken,
    simulatedOtp: challenge.otp,
    expiresInSeconds: challenge.expiresInSeconds
  });
});

app.post('/api/verify-sms-otp', (req, res) => {
  const { challengeToken, otp } = req.body;
  const payload = verifyChallengeToken(challengeToken);

  if (!payload) return res.status(400).json({ status: 'invalid', error: 'Invalid challenge session.' });
  if (Date.now() > payload.expiresAt) return res.status(400).json({ status: 'expired', error: 'Code has expired.' });

  if (payload.otpHash !== hashValue(otp)) {
    const attempts = payload.attempts + 1;
    if (attempts >= 3) {
      return res.status(400).json({ status: 'max_attempts', error: 'Maximum attempts reached.' });
    }
    const updated = issueChallengePayload(payload.userId, payload.channel, payload.recipient, attempts, payload.otp);
    return res.status(400).json({
      status: 'wrong_code',
      error: `Incorrect code. ${3 - attempts} attempt(s) left.`,
      updatedToken: updated.challengeToken
    });
  }

  res.json({ success: true, message: 'Mobile verified and MFA enabled.' });
});

// ----------------------------------------------------
// 2. LOGIN & MFA ENDPOINTS
// ----------------------------------------------------
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const normalizedEmail = email?.toLowerCase().trim();
  const userId = crypto.randomUUID();

  const challenge = issueChallengePayload(userId, 'email', normalizedEmail);
  return res.json({
    mfaRequired: true,
    method: 'email',
    challengeToken: challenge.challengeToken,
    simulatedOtp: challenge.otp,
    email: normalizedEmail,
    expiresInSeconds: challenge.expiresInSeconds
  });
});

app.post('/api/verify-login-otp', (req, res) => {
  const { challengeToken, otp } = req.body;
  const payload = verifyChallengeToken(challengeToken);

  if (!payload) return res.status(400).json({ status: 'invalid', error: 'Invalid challenge session.' });
  if (Date.now() > payload.expiresAt) return res.status(400).json({ status: 'expired', error: 'Code expired.' });

  if (payload.otpHash !== hashValue(otp)) {
    const attempts = payload.attempts + 1;
    if (attempts >= 3) {
      return res.status(400).json({ status: 'max_attempts', error: 'Maximum attempts reached.' });
    }
    const updated = issueChallengePayload(payload.userId, payload.channel, payload.recipient, attempts, payload.otp);
    return res.status(400).json({
      status: 'wrong_code',
      error: `Incorrect code. ${3 - attempts} attempt(s) left.`,
      updatedToken: updated.challengeToken
    });
  }

  // Set stateless session cookie
  setSessionCookie(res, {
    id: payload.userId,
    name: payload.recipient.split('@')[0],
    email: payload.recipient
  });

  res.json({ success: true, message: 'Authentication successful' });
});

// ----------------------------------------------------
// 3. SESSION & PROTECTED ENDPOINTS
// ----------------------------------------------------
app.get('/api/me', (req, res) => {
  const user = getSessionUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Unauthorized: No active session' });
  }
  res.json({ id: user.userId, name: user.name, email: user.email });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('secureid_session');
  res.json({ success: true, message: 'Session invalidated' });
});

// ----------------------------------------------------
// 4. JWT FLOW
// ----------------------------------------------------
app.post('/api/token', (req, res) => {
  const user = getSessionUser(req);
  if (!user) {
    return res.status(401).json({ error: 'Active session required to issue JWT' });
  }
  const token = jwt.sign(
    { sub: user.userId, email: user.email, name: user.name },
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
  try {
    const payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    res.json({
      message: 'Access granted to IAM protected API',
      user: payload,
      issuedAt: new Date(payload.iat * 1000).toISOString()
    });
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired JWT token' });
  }
});

if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
}

module.exports = app;