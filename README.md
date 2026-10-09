# Grove

Express + MongoDB + Razorpay. The database holds only accounts, payments and optional cloud backups. Game progress (tasks, points, pet, focus, dopamine, theme settings) lives in each user's browser (localStorage).

## Run
1. `cp .env.example .env` and fill it in.
2. `npm install` (collections and indexes are created automatically on first start)
3. `npm run dev` then open http://localhost:4000 (the server also serves `public/index.html`).

## API
| Route | Purpose |
|---|---|
| POST /api/auth/register, /login, /logout | bcrypt + JWT in an httpOnly cookie, rate-limited |
| GET /api/me | username, email, Plus status and expiry |
| GET/PUT /api/backup | optional cloud copy of the user's progress (max 200 KB) |
| POST /api/billing/order, /verify, /webhook | Razorpay, price set server-side, signature-checked, idempotent |

## Razorpay
Dashboard > Webhooks > `https://YOUR_DOMAIN/api/billing/webhook`, events `payment.captured`, `order.paid`, `payment.failed`, secret = `RAZORPAY_WEBHOOK_SECRET`. Test with `rzp_test_` keys first.

## Before you go live
HTTPS, `NODE_ENV=production`, Atlas backups and an IP allow-list, privacy policy and terms pages (Razorpay requires them), and password reset / email verification (not included yet).
