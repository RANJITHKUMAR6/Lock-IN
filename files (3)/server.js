import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { MongoClient } from 'mongodb';
import Razorpay from 'razorpay';
import { z } from 'zod';
import { fileURLToPath } from 'node:url';

const env = process.env, PROD = env.NODE_ENV === 'production';
const PRICE = { monthly: +env.PLAN_MONTHLY_INR || 149, yearly: +env.PLAN_YEARLY_INR || 999 };
const DAYS = { monthly: 30, yearly: 365 };
for (const k of ['MONGODB_URI', 'JWT_SECRET']) if (!env[k]) throw new Error(`Missing ${k}`);

const client = new MongoClient(env.MONGODB_URI, { serverSelectionTimeoutMS: 8000 });
try { await client.connect(); } catch (e) { console.error('Could not connect to MongoDB:', e.message); process.exit(1); }
const db = client.db(env.MONGODB_DB || 'grove');
const users = db.collection('users'), payments = db.collection('payments'), events = db.collection('webhook_events'), backups = db.collection('backups');
await users.createIndex({ email: 1 }, { unique: true });
await users.createIndex({ usernameLower: 1 }, { unique: true });
await payments.createIndex({ orderId: 1 }, { unique: true });
const rzp = env.RAZORPAY_KEY_ID ? new Razorpay({ key_id: env.RAZORPAY_KEY_ID, key_secret: env.RAZORPAY_KEY_SECRET }) : null;

const RESERVED = ['admin', 'root', 'grove', 'support', 'claude', 'anthropic', 'moderator', 'null', 'undefined'];
const username = z.string().regex(/^[A-Za-z][A-Za-z0-9_]{2,15}$/, '3–16 chars, start with a letter, letters/numbers/_ only')
  .refine(v => !RESERVED.includes(v.toLowerCase()), 'Reserved name');
const Register = z.object({ email: z.string().email().max(254), username, password: z.string().min(10).max(128) });
const Login = z.object({ email: z.string().email(), password: z.string().min(1).max(128) });

const sha = v => crypto.createHash('sha256').update(v).digest('hex');
async function sendMail(to, subject, html) {
  if (!env.RESEND_API_KEY) { if (!PROD) console.log(`[mail disabled] to=${to}\n${html}`); return; }
  const r = await fetch('https://api.resend.com/emails', { method: 'POST', headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: env.MAIL_FROM || 'Grove <onboarding@resend.dev>', to, subject, html }) });
  if (!r.ok) console.error('Mail failed', r.status, await r.text());
}
const wrap = fn => (req, res, next) => fn(req, res, next).catch(e => e.status ? res.status(e.status).json({ error: e.message }) : next(e));
const fail = (status, message) => Object.assign(new Error(message), { status });
const safeEq = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {          // allows Razorpay Checkout + Google Fonts only
  'script-src': ["'self'", "'unsafe-inline'", 'https://checkout.razorpay.com'],
  'style-src': ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  'font-src': ['https://fonts.gstatic.com'],
  'frame-src': ['https://api.razorpay.com', 'https://checkout.razorpay.com'],
  'connect-src': ["'self'", 'https://api.razorpay.com', 'https://lumberjack.razorpay.com'],
  'img-src': ["'self'", 'data:', 'https:'] } } }));
if (env.CLIENT_ORIGIN) app.use(cors({ origin: env.CLIENT_ORIGIN, credentials: true }));
app.post('/api/billing/webhook', express.raw({ type: 'application/json' }), wrap(webhook)); // raw body BEFORE json parser
app.use(express.json({ limit: '300kb' }));
app.use(cookieParser());
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true });
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 120 }));

const ttl = +env.JWT_TTL_DAYS || 14;
const setCookie = (res, uid) => res.cookie('grove', jwt.sign({ uid }, env.JWT_SECRET, { expiresIn: `${ttl}d` }),
  { httpOnly: true, secure: PROD, sameSite: env.CLIENT_ORIGIN ? 'none' : 'lax', maxAge: ttl * 864e5 });
const auth = (req, _res, next) => { try { req.uid = jwt.verify(req.cookies.grove, env.JWT_SECRET).uid; next(); } catch { next(fail(401, 'Sign in required')); } };

app.get('/api/health', (_q, r) => r.json({ ok: true }));

app.post('/api/auth/register', authLimiter, wrap(async (req, res) => {
  const b = Register.safeParse(req.body); if (!b.success) throw fail(400, b.error.issues[0].message);
  const hash = await bcrypt.hash(b.data.password, +env.BCRYPT_COST || 12);
  const id = crypto.randomUUID();
  try { await users.insertOne({ _id: id, email: b.data.email.toLowerCase(), username: b.data.username, usernameLower: b.data.username.toLowerCase(),
    passHash: hash, planUntil: null, createdAt: new Date() }); }
  catch (e) { if (e.code === 11000) throw fail(409, e.keyPattern?.usernameLower ? 'Username is taken' : 'Email is already registered'); throw e; }
  setCookie(res, id); res.status(201).json({ ok: true });
}));
app.post('/api/auth/login', authLimiter, wrap(async (req, res) => {
  const b = Login.safeParse(req.body); if (!b.success) throw fail(400, 'Invalid email or password');
  const u = await users.findOne({ email: b.data.email.toLowerCase() });
  const ok = await bcrypt.compare(b.data.password, u?.passHash || '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvali');
  if (!u || !ok) throw fail(401, 'Invalid email or password');
  setCookie(res, u._id); res.json({ ok: true });
}));
app.post('/api/auth/logout', (_q, res) => { res.clearCookie('grove'); res.json({ ok: true }); });

// ---------- Password reset: single-use token, stored only as a hash, valid for 1 hour ----------
app.post('/api/auth/forgot', authLimiter, wrap(async (req, res) => {
  const b = z.object({ email: z.string().email() }).safeParse(req.body); if (!b.success) throw fail(400, 'Enter a valid email');
  const u = await users.findOne({ email: b.data.email.toLowerCase() });
  if (u) {
    const token = crypto.randomBytes(32).toString('hex');
    await users.updateOne({ _id: u._id }, { $set: { resetHash: sha(token), resetExpires: new Date(Date.now() + 3600e3) } });
    const link = `${env.APP_URL || 'http://localhost:' + (env.PORT || 4000)}/?reset=${token}`;
    await sendMail(u.email, 'Reset your Grove password',
      `<p>Hi ${u.username},</p><p>Use this link within 1 hour to choose a new password:</p><p><a href="${link}">${link}</a></p><p>If you did not ask for this, you can ignore this email.</p>`).catch(e => console.error(e));
  }
  res.json({ ok: true });                                   // same answer whether or not the email exists
}));
app.post('/api/auth/reset', authLimiter, wrap(async (req, res) => {
  const b = z.object({ token: z.string().length(64), password: z.string().min(10).max(128) }).safeParse(req.body);
  if (!b.success) throw fail(400, 'Use a password of at least 10 characters');
  const hash = await bcrypt.hash(b.data.password, +env.BCRYPT_COST || 12);
  const r = await users.updateOne({ resetHash: sha(b.data.token), resetExpires: { $gt: new Date() } },
    { $set: { passHash: hash }, $unset: { resetHash: '', resetExpires: '' } });
  if (!r.matchedCount) throw fail(400, 'This reset link is invalid or has expired');
  res.json({ ok: true });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const u = await users.findOne({ _id: req.uid });
  if (!u) throw fail(401, 'Sign in required');
  res.json({ id: u._id, email: u.email, username: u.username, plus: !!u.planUntil && u.planUntil > new Date(), plusUntil: u.planUntil });
}));

// ---------- Optional cloud backup (opaque blob; the browser owns the data) ----------
app.get('/api/backup', auth, wrap(async (req, res) => {
  const b = await backups.findOne({ _id: req.uid });
  if (!b) throw fail(404, 'No backup yet'); res.json({ data: b.data, updatedAt: b.updatedAt });
}));
app.put('/api/backup', auth, wrap(async (req, res) => {
  const b = z.object({ data: z.string().max(200000) }).safeParse(req.body); if (!b.success) throw fail(400, 'Backup is too large');
  try { JSON.parse(b.data.data ?? b.data); } catch { throw fail(400, 'Invalid backup'); }
  await backups.updateOne({ _id: req.uid }, { $set: { data: b.data.data, updatedAt: new Date() } }, { upsert: true });
  res.json({ ok: true });
}));

// ---------- Billing (Razorpay one-time orders: 30 or 365 days of Plus) ----------
app.post('/api/billing/order', auth, wrap(async (req, res) => {
  if (!rzp) throw fail(503, 'Payments are not configured');
  const b = z.object({ plan: z.enum(['monthly', 'yearly']) }).safeParse(req.body); if (!b.success) throw fail(400, 'Invalid plan');
  const paise = PRICE[b.data.plan] * 100;                                         // price comes from the server, never the client
  const order = await rzp.orders.create({ amount: paise, currency: 'INR', receipt: `g_${Date.now()}`, notes: { uid: req.uid, plan: b.data.plan } });
  await payments.insertOne({ orderId: order.id, userId: req.uid, plan: b.data.plan, amountPaise: paise, status: 'created', createdAt: new Date() });
  res.json({ orderId: order.id, amount: paise, currency: 'INR', keyId: env.RAZORPAY_KEY_ID });
}));
app.post('/api/billing/verify', auth, wrap(async (req, res) => {
  const b = z.object({ razorpay_order_id: z.string(), razorpay_payment_id: z.string(), razorpay_signature: z.string() }).safeParse(req.body);
  if (!b.success) throw fail(400, 'Invalid payment');
  const sig = crypto.createHmac('sha256', env.RAZORPAY_KEY_SECRET).update(`${b.data.razorpay_order_id}|${b.data.razorpay_payment_id}`).digest('hex');
  if (!safeEq(sig, b.data.razorpay_signature)) throw fail(400, 'Signature mismatch');
  await activate(b.data.razorpay_order_id, b.data.razorpay_payment_id, req.uid);
  res.json({ ok: true });
}));
async function activate(orderId, paymentId, onlyUid) {          // idempotent: only the first call flips status to 'paid'
  const p = await payments.findOneAndUpdate({ orderId, status: { $ne: 'paid' }, ...(onlyUid && { userId: onlyUid }) }, { $set: { status: 'paid', paymentId } });
  if (!p) return;                                                // already paid, unknown order, or not this user's order
  const now = new Date();
  await users.updateOne({ _id: p.userId }, [{ $set: { planUntil: { $dateAdd: { startDate: { $max: [{ $ifNull: ['$planUntil', now] }, now] }, unit: 'day', amount: DAYS[p.plan] } } } }]);
}
async function webhook(req, res) {
  const sig = req.get('x-razorpay-signature') || '';
  const expect = crypto.createHmac('sha256', env.RAZORPAY_WEBHOOK_SECRET || '').update(req.body).digest('hex');
  if (!safeEq(expect, sig)) throw fail(400, 'Bad signature');
  const evt = JSON.parse(req.body.toString()), id = req.get('x-razorpay-event-id');
  const pay = evt.payload?.payment?.entity;
  if (pay && (evt.event === 'payment.captured' || evt.event === 'order.paid')) await activate(pay.order_id, pay.id);
  if (pay && evt.event === 'payment.failed') await payments.updateMany({ orderId: pay.order_id, status: 'created' }, { $set: { status: 'failed' } });
  if (id) await events.updateOne({ _id: id }, { $setOnInsert: { receivedAt: new Date() } }, { upsert: true });
  res.json({ ok: true });
}

app.use(express.static(fileURLToPath(new URL('./public', import.meta.url))));   // serves the app from the same domain
app.use((e, _req, res, _next) => { console.error(e); res.status(500).json({ error: 'Something went wrong' }); });
app.listen(+env.PORT || 4000, () => console.log(`Grove on :${env.PORT || 4000}`));
