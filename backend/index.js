
const express = require('express');
const { Pool } = require('pg');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'craftysogo_db',
  password: 'post20',
  port: 5432,
});

pool.connect((err, client, release) => {
  if (err) {
    return console.error('Error acquiring client', err.stack);
  }
  console.log('Database connected successfully');
  release();
});

app.post('/login', async (req, res) => {
  console.log('Login attempt:', req.body);
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND password = $2', [username, password]);
    console.log('Query result:', result.rows);
    const user = result.rows[0];
    if (!user) {
      console.log('No user found for:', { username, password });
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    console.log('User role (raw):', user.role);
    console.log('User role (trimmed and lowercased):', user.role ? user.role.trim().toLowerCase() : 'undefined');

    if (user.role && user.role.trim().toLowerCase() === 'admin') {
      console.log('Main admin login detected, skipping 2FA for user:', user.username);
      const response = { success: true, role: user.role };
      console.log('Sending response for admin:', response);
      return res.json(response);
    }

    console.log('Non-admin user, proceeding with 2FA for user:', user.username);
    if (!user.is_2fa_setup) {
      console.log('First login for non-admin, generating QR code');
      const secret = speakeasy.generateSecret({ name: `Craftysogo:${username}` });
      await pool.query('UPDATE users SET secret_2fa = $1 WHERE id = $2', [secret.base32, user.id]);
      qrcode.toDataURL(secret.otpauth_url, (err, data_url) => {
        if (err) {
          console.error('QR code generation failed:', err);
          return res.status(500).json({ error: 'QR code generation failed' });
        }
        const response = { qrCode: data_url, userId: user.id, is2FASetup: false };
        console.log('Sending response for non-admin (first login):', response);
        res.json(response);
      });
    } else {
      console.log('Subsequent login for non-admin, requesting 2FA code');
      const response = { userId: user.id, is2FASetup: true };
      console.log('Sending response for non-admin (subsequent login):', response);
      res.json(response);
    }
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/verify-2fa', async (req, res) => {
  console.log('Verify 2FA attempt:', req.body);
  const { userId, token } = req.body;
  const user = (await pool.query('SELECT * FROM users WHERE id = $1', [userId])).rows[0];
  const verified = speakeasy.totp.verify({
    secret: user.secret_2fa,
    encoding: 'base32',
    token,
  });
  console.log('2FA verification result:', verified);
  if (verified) {
    await pool.query('UPDATE users SET is_2fa_setup = TRUE WHERE id = $1', [userId]);
    res.json({ success: true, role: user.role });
  } else {
    res.status(401).json({ error: 'Invalid 2FA code' });
  }
});

app.get('/users', async (req, res) => {
  const result = await pool.query('SELECT id, username, role FROM users');
  res.json(result.rows);
});

app.post('/users', async (req, res) => {
  const { username, password, role } = req.body;
  const result = await pool.query(
    'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *',
    [username, password, role || 'user']
  );
  res.json(result.rows[0]);
});

app.delete('/users/:id', async (req, res) => {
  const { id } = req.params;
  await pool.query('DELETE FROM users WHERE id = $1', [id]);
  res.json({ success: true });
});

app.listen(3000, () => console.log('Server running on port 3000'));