*** Begin Patch
*** Add File: README.md
+# Black Wellness Network — Winter Pilot Starter
+
+This repository contains a starter codebase for the **Black Wellness Network** Cincinnati pilot:
+- Node + Express backend using SQLite (easy local start) with Stripe subscription + webhooks, JWT auth, revenue/payout calculator, CSV export, and email templates (SendGrid or SMTP via nodemailer).
+- React frontend with member / studio / admin views (basic — intended as an MVP).
+
+This repo is intended to run locally for a 3-month pilot (winter) and be portable to Postgres + Render/Vercel for production.
+
+## Quick local start (dev)
+
+1. Backend
+```bash
+cd backend
+npm install
+cp .env.example .env
+# Edit .env to add your test Stripe keys and other values
+node db.js           # creates data.db and seeds founding studios and a test user
+npm start            # start API on http://localhost:4000
+```
+
+2. Frontend
+```bash
+cd frontend
+npm install
+cp .env.example .env
+# Edit .env to set REACT_APP_API_URL=http://localhost:4000
+npm start            # UI on http://localhost:3000
+```
+
+## Important notes
+- This starter uses Stripe test mode for billing. Add `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and `STRIPE_PRICE_ID` to `.env`.
+- For production, migrate SQLite → Postgres (knex migrations are suggested). See `README` guidance below.
+- Use Stripe `stripe listen` during local dev to forward webhooks or deploy backend to a public URL and set the webhook there.
+
+## Pilot rules implemented
+- 3-month pilot flag on subscriptions, `pilot_ends_at` persisted.
+- Notional pilot contribution ($50/mo by default) to allow studio payouts while pilot subscribers pay $0.
+- Hybrid revenue algorithm: per-class host fee + attendance share + studio minimum guarantee.
+- Admin endpoints to compute payouts and export CSV.
+
+If you want a ready zip instead of the patch, tell me and I'll produce the file content in another format.
+
*** End Patch
*** Add File: backend/package.json
+{
+  "name": "black-wellness-network-backend",
+  "version": "0.1.0",
+  "main": "server.js",
+  "scripts": {
+    "start": "node server.js",
+    "seed": "node db.js"
+  },
+  "dependencies": {
+    "bcrypt": "^5.1.0",
+    "better-sqlite3": "^8.0.0",
+    "body-parser": "^1.20.1",
+    "cors": "^2.8.5",
+    "dotenv": "^16.0.0",
+    "express": "^4.18.2",
+    "json2csv": "^5.0.7",
+    "jsonwebtoken": "^9.0.0",
+    "nanoid": "^4.0.0",
+    "nodemailer": "^6.9.3",
+    "raw-body": "^2.5.1",
+    "stripe": "^12.0.0"
+  }
+}
*** End Patch
*** Add File: backend/.env.example
+# Copy to .env and fill values for local testing
+PORT=4000
+APP_BASE_URL=http://localhost:3000
+JWT_SECRET=change_this_jwt_secret_for_dev
+STRIPE_SECRET_KEY=sk_test_yourkey
+STRIPE_WEBHOOK_SECRET=whsec_yourwebhook
+STRIPE_PRICE_ID=price_yourpriceid
+SENDGRID_API_KEY=replace_with_your_sendgrid_key_or_leave_empty
+EMAIL_FROM=no-reply@blackwellness.local
+NOTIONAL_PILOT_CENTS=5000
+HOST_FEE_PER_CLASS_CENTS=2000
+STUDIO_MINIMUM_CENTS=1000
+
*** End Patch
*** Add File: backend/db.js
+// db.js — create local SQLite DB and seed founding studios + admin + sample member
+const Database = require('better-sqlite3');
+const db = new Database('./data.db', {});
+const { nanoid } = require('nanoid');
+
+function run(sql) {
+  db.exec(sql);
+}
+
+run(`
+PRAGMA foreign_keys = ON;
+
+CREATE TABLE IF NOT EXISTS users (
+  id TEXT PRIMARY KEY,
+  name TEXT,
+  email TEXT UNIQUE,
+  role TEXT,
+  studio_id TEXT,
+  created_at TEXT,
+  password_hash TEXT,
+  stripe_customer_id TEXT,
+  stripe_subscription_id TEXT
+);
+
+CREATE TABLE IF NOT EXISTS studios (
+  id TEXT PRIMARY KEY,
+  name TEXT,
+  lead TEXT,
+  email TEXT,
+  neighborhood TEXT,
+  created_at TEXT
+);
+
+CREATE TABLE IF NOT EXISTS subscriptions (
+  id TEXT PRIMARY KEY,
+  user_id TEXT,
+  status TEXT,
+  price_cents INTEGER,
+  started_at TEXT,
+  pilot INTEGER DEFAULT 0,
+  pilot_ends_at TEXT,
+  passes_per_month INTEGER,
+  FOREIGN KEY(user_id) REFERENCES users(id)
+);
+
+CREATE TABLE IF NOT EXISTS classes (
+  id TEXT PRIMARY KEY,
+  studio_id TEXT,
+  title TEXT,
+  starts_at TEXT,
+  capacity INTEGER,
+  created_at TEXT,
+  FOREIGN KEY(studio_id) REFERENCES studios(id)
+);
+
+CREATE TABLE IF NOT EXISTS bookings (
+  id TEXT PRIMARY KEY,
+  user_id TEXT,
+  class_id TEXT,
+  booked_at TEXT,
+  attended INTEGER DEFAULT 0,
+  FOREIGN KEY(user_id) REFERENCES users(id),
+  FOREIGN KEY(class_id) REFERENCES classes(id)
+);
+
+CREATE TABLE IF NOT EXISTS payments (
+  id TEXT PRIMARY KEY,
+  subscription_id TEXT,
+  user_id TEXT,
+  amount_cents INTEGER,
+  stripe_invoice_id TEXT,
+  received_at TEXT
+);
+
+CREATE TABLE IF NOT EXISTS payouts (
+  id TEXT PRIMARY KEY,
+  studio_id TEXT,
+  period_start TEXT,
+  period_end TEXT,
+  amount_cents INTEGER,
+  created_at TEXT,
+  FOREIGN KEY(studio_id) REFERENCES studios(id)
+);
+`);
+
+// Seed studios
+const seedStudios = [
+  { name: 'The Maroon Collective', lead: 'Stella', email: 'stella@marooncollective.example', neighborhood: 'Walnut Hills' },
+  { name: 'Red Dragon Fly Collective', lead: 'Dr. Job Sankofa', email: 'job@reddragonfly.example', neighborhood: 'River Road' },
+  { name: 'The Dealers Club', lead: 'N/A', email: 'info@dealersclub.example', neighborhood: 'Downtown Central Pkwy' },
+  { name: 'Zencinnati', lead: 'Brandy', email: 'brandy@zencinnati.example', neighborhood: 'OTR' },
+  { name: 'The House of Wellness', lead: 'Sosha', email: 'hello@houseofwellness', neighborhood: 'College Hill' },
+  { name: 'Sweet Sister Splash', lead: 'Nzinga', email: 'nzinga@sweetsister.example', neighborhood: 'OTR' },
+  { name: 'Mint Yoga', lead: 'Nikki', email: 'nikki@mintyoga.example', neighborhood: 'Ft Thomas NKY' },
+  { name: 'VBS', lead: 'Lorraine', email: 'lorraine@vbs.example', neighborhood: 'Reading Rd' },
+  { name: 'Kiwi', lead: 'N/A', email: 'hello@kiwi.example', neighborhood: 'OTR' }
+];
+
+const insertStudio = db.prepare('INSERT OR IGNORE INTO studios (id,name,lead,email,neighborhood,created_at) VALUES (?,?,?,?,?,?)');
+for (const s of seedStudios) {
+  insertStudio.run(nanoid(), s.name, s.lead, s.email, s.neighborhood, new Date().toISOString());
+}
+
+// Seed admin
+const insertUser = db.prepare('INSERT OR IGNORE INTO users (id,name,email,role,studio_id,created_at) VALUES (?,?,?,?,?,?)');
+insertUser.run(nanoid(), 'Network Admin', 'admin@blackwellness.local', 'admin', null, new Date().toISOString());
+
+// Seed a sample member with a pilot subscription
+const userId = nanoid();
+insertUser.run(userId, 'Test Member', 'member@example.com', 'member', null, new Date().toISOString());
+
+const insertSub = db.prepare('INSERT INTO subscriptions (id,user_id,status,price_cents,started_at,pilot,pilot_ends_at,passes_per_month) VALUES (?,?,?,?,?,?,?,?)');
+const now = new Date();
+const pilotEnds = new Date(now);
+pilotEnds.setMonth(pilotEnds.getMonth() + 3); // 3 month pilot
+insertSub.run(nanoid(), userId, 'trial', 0, now.toISOString(), 1, pilotEnds.toISOString(), 8);
+
+console.log('DB seeded.');
+db.close();
+
*** End Patch
*** Add File: backend/utils/revenueHybrid.js
+const Database = require('better-sqlite3');
+const db = new Database('./data.db');
+
+function computeRevenueHybrid(start, end, opts = {}) {
+  const HOST_FEE_PER_CLASS_CENTS = parseInt(process.env.HOST_FEE_PER_CLASS_CENTS || opts.hostFeePerClassCents || 2000);
+  const STUDIO_MINIMUM_CENTS = parseInt(process.env.STUDIO_MINIMUM_CENTS || opts.studioMinimumCents || 1000);
+  const NOTIONAL_PER_PILOT_CENTS = parseInt(process.env.NOTIONAL_PILOT_CENTS || opts.notionalPerPilotCents || 5000);
+  const ATTENDANCE_WEIGHT = opts.attendanceWeight ?? 0.6;
+  const MARKETING_SHARE = opts.marketingShare ?? 0.2;
+
+  const payments = db.prepare('SELECT SUM(amount_cents) as total FROM payments WHERE received_at BETWEEN ? AND ?').get(start, end);
+  const totalPayments = payments.total || 0;
+
+  const pilotSubs = db.prepare('SELECT COUNT(*) as c FROM subscriptions WHERE pilot = 1 AND started_at <= ?').get(end).c || 0;
+  const pilotNotionalTotal = pilotSubs * NOTIONAL_PER_PILOT_CENTS;
+
+  const pool = totalPayments + pilotNotionalTotal;
+
+  // classes during period
+  const classes = db.prepare('SELECT id, studio_id FROM classes WHERE starts_at BETWEEN ? AND ?').all(start, end);
+  const classesByStudio = {};
+  classes.forEach(c => { classesByStudio[c.studio_id] = (classesByStudio[c.studio_id] || 0) + 1; });
+
+  // attendance
+  const attendedRows = db.prepare(`
+    SELECT c.studio_id, s.name as studio_name, COUNT(b.id) as attended_count
+    FROM bookings b
+    JOIN classes c ON c.id = b.class_id
+    JOIN studios s ON s.id = c.studio_id
+    WHERE b.attended = 1
+      AND b.booked_at BETWEEN ? AND ?
+    GROUP BY c.studio_id
+  `).all(start, end);
+
+  const totalAttendance = attendedRows.reduce((s,r)=> s + r.attended_count, 0) || 0;
+
+  const attendancePool = Math.round(pool * ATTENDANCE_WEIGHT);
+  const marketingPool = Math.round(pool * MARKETING_SHARE);
+  const adminPool = pool - attendancePool - marketingPool;
+
+  const distribution = [];
+  for (const r of attendedRows) {
+    const studioId = r.studio_id;
+    const attended = r.attended_count;
+    const attendanceShare = totalAttendance ? Math.round(attendancePool * (attended / totalAttendance)) : 0;
+    const hostFee = classesByStudio[studioId] ? (classesByStudio[studioId] * HOST_FEE_PER_CLASS_CENTS) : 0;
+    const amount = Math.max(STUDIO_MINIMUM_CENTS, hostFee + attendanceShare);
+    distribution.push({
+      studio_id: studioId,
+      studio_name: r.studio_name,
+      attended_count: attended,
+      host_fee_cents: hostFee,
+      attendance_share_cents: attendanceShare,
+      amount_cents: amount
+    });
+  }
+
+  // include studios with classes but no attendance
+  for (const [studio_id, count] of Object.entries(classesByStudio)) {
+    if (!distribution.find(d => d.studio_id === studio_id)) {
+      const hostFee = count * HOST_FEE_PER_CLASS_CENTS;
+      const amount = Math.max(STUDIO_MINIMUM_CENTS, hostFee);
+      const studio = db.prepare('SELECT name FROM studios WHERE id = ?').get(studio_id);
+      distribution.push({
+        studio_id,
+        studio_name: studio ? studio.name : 'Unknown',
+        attended_count: 0,
+        host_fee_cents: hostFee,
+        attendance_share_cents: 0,
+        amount_cents: amount
+      });
+    }
+  }
+
+  const studiosPool = Math.round(pool * (1 - MARKETING_SHARE - (1 - ATTENDANCE_WEIGHT - MARKETING_SHARE))); // keep compatible
+  const totalDistributed = distribution.reduce((s,d)=> s + d.amount_cents, 0);
+  if (totalDistributed > studiosPool && totalDistributed > 0) {
+    const scale = studiosPool / totalDistributed;
+    distribution.forEach(d => { d.amount_cents = Math.round(d.amount_cents * scale); });
+  }
+
+  return {
+    pool, totalPayments, pilotNotionalTotal, attendancePool, marketingPool, adminPool,
+    distribution
+  };
+}
+
+module.exports = { computeRevenueHybrid };
+
*** End Patch
*** Add File: backend/server.js
+require('dotenv').config();
+const express = require('express');
+const cors = require('cors');
+const bodyParser = require('body-parser');
+const Database = require('better-sqlite3');
+const { nanoid } = require('nanoid');
+const jwt = require('jsonwebtoken');
+const bcrypt = require('bcrypt');
+const rawBody = require('raw-body');
+const Stripe = require('stripe');
+const { Parser } = require('json2csv');
+const nodemailer = require('nodemailer');
+const { computeRevenueHybrid } = require('./utils/revenueHybrid');
+
+const stripe = Stripe(process.env.STRIPE_SECRET_KEY || '');
+const db = new Database('./data.db');
+const app = express();
+app.use(cors());
+app.use(bodyParser.json());
+
+function nowISO() { return new Date().toISOString(); }
+
+// Simple email transport (use real provider in production)
+const transporter = nodemailer.createTransport({
+  // for local dev you can use Mailtrap or SMTP
+  host: 'smtp.example.local',
+  port: 587,
+  secure: false,
+  auth: { user: '', pass: '' }
+});
+
+// --------------------------
+// Authentication
+// --------------------------
+app.post('/auth/register', async (req, res) => {
+  const { name, email, password, role='member', studio_id=null } = req.body;
+  const exists = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
+  if (exists) return res.status(400).json({ error: 'User exists' });
+  const hash = await bcrypt.hash(password, 10);
+  const id = nanoid();
+  db.prepare('INSERT INTO users (id,name,email,role,studio_id,created_at,password_hash) VALUES (?,?,?,?,?,?,?)')
+    .run(id, name, email, role, studio_id, nowISO(), hash);
+  const token = jwt.sign({ id, role }, process.env.JWT_SECRET || 'devsecret', { expiresIn: '30d' });
+  res.json({ token, user: { id, name, email, role, studio_id } });
+});
+
+app.post('/auth/login', async (req, res) => {
+  const { email, password } = req.body;
+  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
+  if (!user) return res.status(401).json({ error: 'Invalid' });
+  const ok = await bcrypt.compare(password, user.password_hash || '');
+  if (!ok) return res.status(401).json({ error: 'Invalid' });
+  const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET || 'devsecret', { expiresIn: '30d' });
+  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, studio_id: user.studio_id } });
+});
+
+function authMiddleware(req, res, next){
+  const auth = req.headers.authorization;
+  if (!auth) return res.status(401).json({ error: 'Missing token' });
+  const token = auth.replace('Bearer ', '');
+  try {
+    const payload = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');
+    req.user = payload;
+    next();
+  } catch (err) {
+    return res.status(401).json({ error: 'Invalid token' });
+  }
+}
+
+// --------------------------
+// Public & basic routes
+// --------------------------
+app.get('/studios', (req, res) => {
+  const rows = db.prepare('SELECT * FROM studios').all();
+  res.json(rows);
+});
+
+app.get('/classes', (req, res) => {
+  const { studio_id } = req.query;
+  if (studio_id) {
+    const rows = db.prepare('SELECT * FROM classes WHERE studio_id = ? ORDER BY starts_at').all(studio_id);
+    res.json(rows);
+  } else {
+    const rows = db.prepare('SELECT * FROM classes ORDER BY starts_at').all();
+    res.json(rows);
+  }
+});
+
+// --------------------------
+// Subscription & billing (Stripe Checkout + webhook)
+// --------------------------
+app.post('/create-checkout-session', async (req, res) => {
+  const { user } = req.body;
+  let localUser = db.prepare('SELECT * FROM users WHERE email = ?').get(user.email);
+  if (!localUser) {
+    const uid = nanoid();
+    db.prepare('INSERT INTO users (id,name,email,role,created_at) VALUES (?,?,?,?,?)')
+      .run(uid, user.name, user.email, 'member', nowISO());
+    localUser = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
+  }
+  if (!localUser.stripe_customer_id) {
+    const customer = await stripe.customers.create({ email: user.email, name: user.name });
+    db.prepare('UPDATE users SET stripe_customer_id = ? WHERE id = ?').run(customer.id, localUser.id);
+    localUser.stripe_customer_id = customer.id;
+  }
+  const session = await stripe.checkout.sessions.create({
+    mode: 'subscription',
+    payment_method_types: ['card'],
+    customer: localUser.stripe_customer_id,
+    line_items: [{ price: process.env.STRIPE_PRICE_ID, quantity: 1 }],
+    success_url: `${process.env.APP_BASE_URL || 'http://localhost:3000'}/success?session_id={CHECKOUT_SESSION_ID}`,
+    cancel_url: `${process.env.APP_BASE_URL || 'http://localhost:3000'}/cancel`,
+  });
+  res.json({ url: session.url });
+});
+
+// webhook (raw body)
+app.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
+  const sig = req.headers['stripe-signature'];
+  let event;
+  try {
+    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
+  } catch (err) {
+    console.error('Webhook signature verification failed.', err.message);
+    return res.status(400).send(`Webhook Error: ${err.message}`);
+  }
+  try {
+    switch (event.type) {
+      case 'checkout.session.completed': {
+        const session = event.data.object;
+        const customerId = session.customer;
+        const stripeSubId = session.subscription;
+        const user = db.prepare('SELECT * FROM users WHERE stripe_customer_id = ?').get(customerId);
+        if (user) {
+          const sub = await stripe.subscriptions.retrieve(stripeSubId);
+          const price = (sub.items.data[0].price.unit_amount || 0);
+          const sid = nanoid();
+          db.prepare(`INSERT INTO subscriptions (id,user_id,status,price_cents,started_at,pilot,passes_per_month) VALUES (?,?,?,?,?,?,?)`)
+            .run(sid, user.id, 'active', price, new Date(sub.current_period_start*1000).toISOString(), 0, 10);
+          db.prepare('UPDATE users SET stripe_subscription_id = ? WHERE id = ?').run(stripeSubId, user.id);
+        }
+        break;
+      }
+      case 'invoice.payment_succeeded': {
+        const invoice = event.data.object;
+        const stripeSubId = invoice.subscription;
+        const user = db.prepare('SELECT * FROM users WHERE stripe_subscription_id = ?').get(stripeSubId);
+        if (user) {
+          db.prepare('UPDATE subscriptions SET status = ? WHERE user_id = ? AND pilot = 0').run('active', user.id);
+          // record payment
+          const pid = nanoid();
+          db.prepare('INSERT INTO payments (id,subscription_id,user_id,amount_cents,stripe_invoice_id,received_at) VALUES (?,?,?,?,?,?)')
+            .run(pid, stripeSubId, user.id, invoice.amount_paid, invoice.id, new Date(invoice.status_transitions?.paid_at*1000 || Date.now()).toISOString());
+        }
+        break;
+      }
+      case 'customer.subscription.deleted': {
+        const sub = event.data.object;
+        const stripeSubId = sub.id;
+        const user = db.prepare('SELECT * FROM users WHERE stripe_subscription_id = ?').get(stripeSubId);
+        if (user) {
+          db.prepare('UPDATE subscriptions SET status = ? WHERE user_id = ?').run('cancelled', user.id);
+        }
+        break;
+      }
+      default:
+        console.log(`Unhandled event type ${event.type}`);
+    }
+    res.json({ received: true });
+  } catch (err) {
+    console.error('Webhook processing error', err);
+    res.status(500).send();
+  }
+});
+
+// --------------------------
+// Booking & attendance
+// --------------------------
+app.post('/book', authMiddleware, (req, res) => {
+  const { class_id } = req.body;
+  const user_id = req.user.id;
+  const id = nanoid();
+  db.prepare('INSERT INTO bookings (id,user_id,class_id,booked_at) VALUES (?,?,?,?)')
+    .run(id, user_id, class_id, nowISO());
+  res.json({ ok:true, booking_id: id });
+});
+
+app.post('/attend', authMiddleware, (req, res) => {
+  const { booking_id } = req.body;
+  // only owners/admins should mark attendance — this endpoint assumes client enforces role
+  db.prepare('UPDATE bookings SET attended = 1 WHERE id = ?').run(booking_id);
+  res.json({ ok: true });
+});
+
+// --------------------------
+// Admin: Revenue / Payouts
+// --------------------------
+app.get('/revenue/period', authMiddleware, (req, res) => {
+  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Not allowed' });
+  const { start, end } = req.query;
+  const startISO = start ? new Date(start).toISOString() : new Date(0).toISOString();
+  const endISO = end ? new Date(end).toISOString() : new Date().toISOString();
+  const result = computeRevenueHybrid(startISO, endISO);
+  res.json(result);
+});
+
+app.post('/admin/generate-payouts', authMiddleware, (req, res) => {
+  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Not allowed' });
+  const { start, end } = req.body;
+  const startISO = new Date(start).toISOString();
+  const endISO = new Date(end).toISOString();
+  const revenueResult = computeRevenueHybrid(startISO, endISO);
+  const insert = db.prepare('INSERT INTO payouts (id,studio_id,period_start,period_end,amount_cents,created_at) VALUES (?,?,?,?,?,?)');
+  const created = [];
+  for (const d of revenueResult.distribution) {
+    const pid = nanoid();
+    insert.run(pid, d.studio_id, start, end, d.amount_cents, nowISO());
+    created.push({ payout_id: pid, studio_id: d.studio_id, studio_name: d.studio_name, amount_dollars: (d.amount_cents/100).toFixed(2) });
+  }
+  const fields = ['payout_id','studio_id','studio_name','amount_dollars'];
+  const parser = new Parser({ fields });
+  const csv = parser.parse(created);
+  res.setHeader('Content-disposition', `attachment; filename=payouts_${start}_${end}.csv`);
+  res.set('Content-Type', 'text/csv');
+  res.status(200).send(csv);
+});
+
+// --------------------------
+// Simple email endpoints (templates)
+// --------------------------
+app.post('/email/pilot-onboard', authMiddleware, async (req, res) => {
+  const { to, name, start_date, end_date, login_url, directory_url } = req.body;
+  const subject = 'Welcome — Black Wellness Network Winter Pilot (3 months)';
+  const text = `Hi ${name},\n\nWelcome to the Black Wellness Network — you're in! This is your 3-month winter pilot membership from ${start_date} to ${end_date}.\n\nLog in: ${login_url}\nBrowse studios: ${directory_url}\n\n— The Black Wellness Network`;
+  try {
+    await transporter.sendMail({ from: process.env.EMAIL_FROM, to, subject, text });
+    res.json({ ok: true });
+  } catch (err) {
+    console.error('Email send failed', err);
+    res.status(500).json({ error: 'Email failed' });
+  }
+});
+
+// --------------------------
+// Misc admin helpers
+// --------------------------
+app.get('/admin/payouts', authMiddleware, (req, res) => {
+  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Not allowed' });
+  const rows = db.prepare('SELECT * FROM payouts ORDER BY created_at DESC').all();
+  res.json(rows);
+});
+
+const PORT = process.env.PORT || 4000;
+app.listen(PORT, () => console.log('API listening on', PORT));
+
*** End Patch
*** Add File: frontend/package.json
+{
+  "name": "black-wellness-frontend",
+  "version": "0.1.0",
+  "private": true,
+  "dependencies": {
+    "axios": "^1.4.0",
+    "react": "^18.2.0",
+    "react-dom": "^18.2.0",
+    "react-router-dom": "^6.14.1",
+    "react-scripts": "5.0.1"
+  },
+  "scripts": {
+    "start": "react-scripts start",
+    "build": "react-scripts build"
+  }
+}
*** End Patch
*** Add File: frontend/.env.example
+REACT_APP_API_URL=http://localhost:4000
+
*** End Patch
*** Add File: frontend/src/index.js
+import React from 'react';
+import { createRoot } from 'react-dom/client';
+import App from './App';
+import './styles.css';
+
+const container = document.getElementById('root');
+const root = createRoot(container);
+root.render(<App />);
+
*** End Patch
*** Add File: frontend/src/App.js
+import React from 'react';
+import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
+import Directory from './pages/Directory';
+import MemberDashboard from './pages/MemberDashboard';
+import StudioDashboard from './pages/StudioDashboard';
+import AdminDashboard from './pages/AdminDashboard';
+
+function App(){
+  return (
+    <BrowserRouter>
+      <div style={{padding:20, fontFamily:'system-ui, sans-serif'}}>
+        <header style={{display:'flex', gap:12, marginBottom:20, alignItems:'center'}}>
+          <h1 style={{margin:0}}>Black Wellness Network — Pilot</h1>
+          <nav>
+            <Link to="/">Directory</Link> {' | '}
+            <Link to="/member">Member</Link> {' | '}
+            <Link to="/studio">Studio</Link> {' | '}
+            <Link to="/admin">Admin</Link>
+          </nav>
+        </header>
+        <Routes>
+          <Route path="/" element={<Directory/>}/>
+          <Route path="/member" element={<MemberDashboard/>}/>
+          <Route path="/studio" element={<StudioDashboard/>}/>
+          <Route path="/admin" element={<AdminDashboard/>}/>
+        </Routes>
+      </div>
+    </BrowserRouter>
+  );
+}
+export default App;
+
*** End Patch
*** Add File: frontend/src/api.js
+import axios from 'axios';
+const API = axios.create({ baseURL: process.env.REACT_APP_API_URL || 'http://localhost:4000' });
+
+export const getStudios = () => API.get('/studios').then(r => r.data);
+export const getClasses = (studio_id) => API.get('/classes', { params: { studio_id } }).then(r => r.data);
+export const subscribe = (payload) => API.post('/subscribe', payload).then(r => r.data);
+export const createCheckout = (payload) => API.post('/create-checkout-session', payload).then(r => r.data);
+export const bookClass = (payload) => API.post('/book', payload).then(r => r.data);
+export const markAttend = (payload) => API.post('/attend', payload).then(r => r.data);
+export const revenueForPeriod = (start, end) => API.get('/revenue/period', { params: { start, end } }).then(r => r.data);
+
*** End Patch
*** Add File: frontend/src/pages/Directory.js
+import React, { useEffect, useState } from 'react';
+import { getStudios } from '../api';
+
+export default function Directory(){
+  const [studios, setStudios] = useState([]);
+  useEffect(()=> { getStudios().then(setStudios) }, []);
+  return (
+    <div>
+      <h2>Founding Studios — Cincinnati Pilot</h2>
+      <ul>
+        {studios.map(s => (
+          <li key={s.id}>
+            <strong>{s.name}</strong> — {s.neighborhood} — {s.lead || 'lead N/A'} — <a href={`mailto:${s.email}`}>{s.email}</a>
+          </li>
+        ))}
+      </ul>
+      <p>Tip: members can subscribe on the Member page (trial available for the 3‑month winter pilot).</p>
+    </div>
+  );
+}
+
*** End Patch
*** Add File: frontend/src/pages/MemberDashboard.js
+import React, { useEffect, useState } from 'react';
+import { getStudios, createCheckout, getClasses } from '../api';
+
+export default function MemberDashboard(){
+  const [name,setName] = useState('Test Member');
+  const [email,setEmail] = useState('member@example.com');
+  const [studios,setStudios] = useState([]);
+  const [classes,setClasses] = useState([]);
+
+  useEffect(()=> getStudios().then(setStudios), []);
+  async function handleCheckoutSubscribe(){
+    const resp = await createCheckout({ user:{ name, email } });
+    if (resp && resp.url) window.location.href = resp.url;
+  }
+  async function loadClasses(studio_id){
+    const cls = await getClasses(studio_id);
+    setClasses(cls);
+  }
+  return (
+    <div>
+      <h2>Member Dashboard — Pilot</h2>
+      <div style={{display:'flex', gap:20}}>
+        <div style={{flex:1}}>
+          <h3>Subscribe (Stripe checkout)</h3>
+          <input placeholder="Full name" value={name} onChange={e=>setName(e.target.value)} /><br/>
+          <input placeholder="Email" value={email} onChange={e=>setEmail(e.target.value)} /><br/>
+          <button onClick={handleCheckoutSubscribe}>Subscribe / Join Pilot</button>
+        </div>
+        <div style={{flex:2}}>
+          <h3>Studios</h3>
+          <ul>
+            {studios.map(s => (
+              <li key={s.id}>
+                <b>{s.name}</b> — {s.neighborhood} — <button onClick={()=>loadClasses(s.id)}>View classes</button>
+              </li>
+            ))}
+          </ul>
+          <h4>Classes</h4>
+          <ul>
+            {classes.map(c => (
+              <li key={c.id}>
+                {c.title} — {new Date(c.starts_at).toLocaleString()} — <button disabled>Book (login required)</button>
+              </li>
+            ))}
+          </ul>
+        </div>
+      </div>
+    </div>
+  );
+}
+
*** End Patch
*** Add File: frontend/src/pages/StudioDashboard.js
+import React from 'react';
+
+export default function StudioDashboard(){
+  return (
+    <div>
+      <h2>Studio Dashboard (simple)</h2>
+      <p>This view can be extended to show classes, bookings, check-in buttons (admin/owner only).</p>
+    </div>
+  );
+}
+
*** End Patch
*** Add File: frontend/src/pages/AdminDashboard.js
+import React, { useState } from 'react';
+import axios from 'axios';
+
+export default function AdminDashboard(){
+  const [start, setStart] = useState('');
+  const [end, setEnd] = useState('');
+  const [csvUrl, setCsvUrl] = useState(null);
+
+  async function genPayouts(){
+    const token = localStorage.getItem('token');
+    const resp = await axios.post(`${process.env.REACT_APP_API_URL || 'http://localhost:4000'}/admin/generate-payouts`, { start, end }, {
+      headers: { Authorization: 'Bearer ' + token },
+      responseType: 'blob'
+    });
+    const blob = new Blob([resp.data], { type: 'text/csv' });
+    const u = URL.createObjectURL(blob);
+    setCsvUrl(u);
+  }
+  return (
+    <div>
+      <h2>Admin Dashboard</h2>
+      <div>
+        <label>Start: <input type="date" value={start} onChange={e=>setStart(e.target.value)} /></label>
+        <label>End: <input type="date" value={end} onChange={e=>setEnd(e.target.value)} /></label>
+        <button onClick={genPayouts}>Generate Payouts CSV</button>
+        {csvUrl && <p><a href={csvUrl} download={`payouts_${start}_${end}.csv`}>Download payouts CSV</a></p>}
+      </div>
+    </div>
+  );
+}
+
*** End Patch
*** Add File: frontend/src/styles.css
+body { margin: 0; padding: 0; font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial; }
+a { color: #0a66c2; }
+input { margin: 6px 0; padding:6px; width: 100%; max-width: 360px; }
+button { padding: 8px 12px; margin-top: 6px; }
+
*** End Patch
*** End Patch
