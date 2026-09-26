require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const { z } = require('zod');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: '*' }
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL
});

app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL || '*'
}));

app.disable('x-powered-by');

app.use(express.json({
  limit: '2mb'
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300
}));

const sign = u =>
  jwt.sign(
    {
      id: u.id,
      role: u.role,
      name: u.name
    },
    process.env.JWT_SECRET,
    {
      expiresIn: '7d'
    }
  );

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';

    if (!h.startsWith('Bearer ')) {
      return res.status(401).json({
        error: 'Non authentifié'
      });
    }

    req.user = jwt.verify(
      h.slice(7),
      process.env.JWT_SECRET
    );

    next();
  } catch (e) {
    res.status(401).json({
      error: 'Session invalide'
    });
  }
}

function role(...roles) {
  return (req, res, next) =>
    roles.includes(req.user.role)
      ? next()
      : res.status(403).json({
          error: 'Accès refusé'
        });
}

const asyncRoute = fn =>
  (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);

app.get('/health', (req, res) =>
  res.json({
    ok: true,
    name: 'Au service de peuples',
    version: '2.0.0'
  })
);

app.post('/api/auth/register', asyncRoute(async (req, res) => {
  const s = z.object({
    name: z.string().min(2),
    phone: z.string().min(6),
    password: z.string().min(6),
    role: z.enum(['client', 'professional'])
  }).parse(req.body);

  const hash = await bcrypt.hash(s.password, 12);

  const q = await pool.query(
    `INSERT INTO users(name,phone,password_hash,role)
     VALUES($1,$2,$3,$4)
     RETURNING id,name,phone,role`,
    [s.name, s.phone, hash, s.role]
  );

  const u = q.rows[0];

  if (u.role === 'professional') {
    await pool.query(
      `INSERT INTO professional_profiles(user_id,trade)
       VALUES($1,$2)`,
      [u.id, 'À définir']
    );
  }

  res.status(201).json({
    token: sign(u),
    user: u
  });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const s = z.object({
    phone: z.string(),
    password: z.string()
  }).parse(req.body);

  const q = await pool.query(
    'SELECT * FROM users WHERE phone=$1',
    [s.phone]
  );

  if (
    !q.rowCount ||
    !(await bcrypt.compare(
      s.password,
      q.rows[0].password_hash
    ))
  ) {
    return res.status(401).json({
      error: 'Identifiants incorrects'
    });
  }

  const u = q.rows[0];

  res.json({
    token: sign(u),
    user: {
      id: u.id,
      name: u.name,
      phone: u.phone,
      role: u.role
    }
  });
}));

app.get('/api/me', auth, asyncRoute(async (req, res) => {
  const q = await pool.query(
    `SELECT id,name,phone,role,created_at
     FROM users
     WHERE id=$1`,
    [req.user.id]
  );

  res.json(q.rows[0]);
}));

app.get('/api/professionals', auth, asyncRoute(async (req, res) => {
  const trade = (req.query.trade || '').trim();

  const q = await pool.query(
    `SELECT
       u.id,
       u.name,
       u.phone,
       p.trade,
       p.bio,
       p.city,
       p.latitude,
       p.longitude,
       p.verified,
       p.rating,
       p.jobs_count
     FROM users u
     JOIN professional_profiles p
       ON p.user_id=u.id
     WHERE u.role='professional'
       AND p.verification_status='approved'
       AND ($1='' OR lower(p.trade)=lower($1))
     ORDER BY p.verified DESC,p.rating DESC`,
    [trade]
  );

  res.json(q.rows);
}));

app.put('/api/professionals/me', auth, role('professional'), asyncRoute(async (req, res) => {
  const s = z.object({
    trade: z.string().min(2),
    bio: z.string().max(1000).optional(),
    city: z.string().optional(),
    latitude: z.number().optional(),
    longitude: z.number().optional(),
    document_url: z.string().url().optional()
  }).parse(req.body);

  const q = await pool.query(
    `UPDATE professional_profiles
     SET trade=$1,
         bio=COALES
