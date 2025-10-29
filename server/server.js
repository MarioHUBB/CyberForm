require('dotenv').config();

const MASTER_KEY_B64 = process.env.MASTER_KEY_BASE64;
const API_TOKEN = process.env.API_TOKEN;

if (!MASTER_KEY_B64 || !API_TOKEN) {
  console.error('Missing MASTER_KEY_BASE64 or API_TOKEN in environment.');
  process.exit(1);
}

const MASTER_KEY = Buffer.from(MASTER_KEY_B64, 'base64'); // 32 bytes

// server.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(helmet());
app.use(express.json({ limit: '1mb' }));
app.use(cors({
  origin: ['http://127.0.0.1:5500'] // adjust if you deploy elsewhere
}));

// Rate limiter
const limiter = rateLimit({ windowMs: 60*1000, max: 30 });
app.use(limiter);

// Simple token auth
function requireToken(req, res, next) {
  //const t = req.get('x-api-token') || '';
  //if (t !== API_TOKEN) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// AES-GCM encryption
function serverEncrypt(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_KEY, iv, { authTagLength: 16 });
  const ct = Buffer.concat([cipher.update(Buffer.from(plainText, 'utf8')), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]).toString('base64');
}

function serverDecrypt(b64blob) {
  const raw = Buffer.from(b64blob, 'base64');
  if (raw.length < (12 + 16 + 1)) throw new Error('Invalid input length');
  const iv = raw.slice(0, 12);
  const tag = raw.slice(12, 28);
  const ct = raw.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_KEY, iv, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString('utf8');
}

// Endpoints
app.post('/api/encrypt', requireToken, (req, res) => {
  try {
    const { plaintext } = req.body;
    if (typeof plaintext !== 'string' || !plaintext.length) {
      return res.status(400).json({ error: 'plaintext required' });
    }
    const ciphertext = serverEncrypt(plaintext);
    return res.json({ ciphertext });
  } catch (err) {
    console.error('encrypt error', err);
    return res.status(500).json({ error: 'internal error' });
  }
});

app.post('/api/decrypt', requireToken, (req, res) => {
  try {
    const { ciphertext } = req.body;
    if (typeof ciphertext !== 'string' || !ciphertext.length) {
      return res.status(400).json({ error: 'ciphertext required' });
    }
    const plaintext = serverDecrypt(ciphertext);
    return res.json({ plaintext });
  } catch (err) {
    console.error('decrypt error', err.message);
    return res.status(400).json({ error: 'decryption failed' });
  }
});

app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
