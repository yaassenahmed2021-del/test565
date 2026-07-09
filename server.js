require('dotenv').config();
const express = require('express');
const cors = require('cors');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- middleware ----------
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
}));

// ---------- mail transporter ----------
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === 'true', // true for port 465, false for 587/25
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// verify SMTP connection on boot so misconfiguration is obvious immediately
transporter.verify((err) => {
  if (err) {
    console.error('❌ SMTP connection failed:', err.message);
    console.error('Check your .env SMTP_* values.');
  } else {
    console.log('✅ SMTP connection OK, ready to send emails.');
  }
});

// ---------- in-memory stores ----------
// NOTE: this is fine for a single Node.js process on one server.
// If you ever run multiple server instances/processes, move this to
// Redis (or a database) instead of an in-memory Map.
const otpStore = new Map();      // key -> { code, expiresAt, attempts }
const lastSentAt = new Map();    // key -> timestamp (basic rate limiting)

const OTP_TTL_MS = 10 * 60 * 1000;      // code valid for 10 minutes
const RESEND_COOLDOWN_MS = 45 * 1000;   // must wait 45s between sends
const MAX_ATTEMPTS = 5;                 // max wrong-code attempts before code is invalidated

function keyFor(email, purpose) {
  return `${String(email).trim().toLowerCase()}|${purpose}`;
}

function genCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// periodic cleanup of expired codes so the Map doesn't grow forever
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of otpStore.entries()) {
    if (now > entry.expiresAt) otpStore.delete(key);
  }
}, 5 * 60 * 1000);

// ---------- routes ----------

app.get('/health', (req, res) => {
  res.json({ ok: true, service: 'talentflow-otp-backend' });
});

app.post('/api/send-otp', async (req, res) => {
  try {
    const { email, purpose } = req.body || {};

    if (!isValidEmail(email)) {
      return res.status(400).json({ ok: false, error: 'invalid_email' });
    }
    if (!['register', 'forgot'].includes(purpose)) {
      return res.status(400).json({ ok: false, error: 'invalid_purpose' });
    }

    const key = keyFor(email, purpose);

    // basic per-email rate limiting
    const last = lastSentAt.get(key) || 0;
    if (Date.now() - last < RESEND_COOLDOWN_MS) {
      return res.status(429).json({ ok: false, error: 'rate_limited' });
    }

    const code = genCode();
    otpStore.set(key, {
      code,
      expiresAt: Date.now() + OTP_TTL_MS,
      attempts: 0,
    });
    lastSentAt.set(key, Date.now());

    const isRegister = purpose === 'register';
    const subject = isRegister
      ? 'رمز تفعيل حسابك في TalentFlow Soft'
      : 'رمز استعادة كلمة المرور - TalentFlow Soft';

    const html = `
      <div style="font-family:Tahoma,Arial,sans-serif;direction:rtl;text-align:right;max-width:480px;margin:0 auto;padding:24px;">
        <h2 style="color:#122A4E;margin-bottom:8px;">${isRegister ? 'تفعيل حسابك' : 'استعادة كلمة المرور'}</h2>
        <p style="color:#444;font-size:14px;line-height:1.7;">
          استخدم رمز التحقق التالي لإكمال العملية على TalentFlow Soft.
          الرمز صالح لمدة 10 دقائق فقط.
        </p>
        <div style="font-size:34px;font-weight:800;letter-spacing:10px;background:#f2f6f8;color:#1E5C81;padding:16px 10px;border-radius:12px;text-align:center;margin:20px 0;">
          ${code}
        </div>
        <p style="color:#888;font-size:12.5px;line-height:1.6;">
          إذا لم تطلب هذا الرمز، يمكنك تجاهل هذه الرسالة بأمان — لن يتم اتخاذ أي إجراء على حسابك.
        </p>
      </div>
    `;

    await transporter.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER,
      to: email,
      subject,
      html,
    });

    return res.json({ ok: true });
  } catch (err) {
    console.error('send-otp error:', err);
    return res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.post('/api/verify-otp', (req, res) => {
  const { email, purpose, code } = req.body || {};

  if (!isValidEmail(email) || !['register', 'forgot'].includes(purpose) || !code) {
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  }

  const key = keyFor(email, purpose);
  const entry = otpStore.get(key);

  if (!entry) {
    return res.status(400).json({ ok: false, error: 'no_pending_code' });
  }
  if (Date.now() > entry.expiresAt) {
    otpStore.delete(key);
    return res.status(400).json({ ok: false, error: 'expired' });
  }

  entry.attempts += 1;
  if (entry.attempts > MAX_ATTEMPTS) {
    otpStore.delete(key);
    return res.status(429).json({ ok: false, error: 'too_many_attempts' });
  }

  if (String(code).trim() !== entry.code) {
    return res.status(400).json({ ok: false, error: 'invalid_code' });
  }

  // success — one-time use, remove it
  otpStore.delete(key);
  return res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`🚀 OTP backend listening on port ${PORT}`);
});