# CivicAssist deployment — Render staging

This package is prepared for an initial public staging deployment on Render.

## Important
- Do NOT commit `.env` or any Razorpay secret.
- This current prototype uses a JSON datastore and local uploads. Render's free service filesystem is ephemeral, so this is suitable for website verification/testing, NOT for storing real customer documents or operating a production business.
- Before accepting real customer data, migrate the database and document storage to persistent/managed services and complete a security review.

## Render settings
- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Health check: `/`

## Environment variables later
- `NODE_ENV=production`
- `RAZORPAY_KEY_ID=...`
- `RAZORPAY_KEY_SECRET=...`
- `RAZORPAY_WEBHOOK_SECRET=...`

Keep secrets only in Render Environment Variables. Never put them in GitHub or the browser.
