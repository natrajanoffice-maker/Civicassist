# CivicAssist — Stage 3 + 4

## What is implemented

### Stage 3 — private documents
- Customer authentication required before upload.
- Maximum 5 files per request.
- Maximum 10 MB per file.
- Allowed extensions: PDF, JPG/JPEG, PNG, DOC/DOCX.
- Files are stored outside `public/`.
- Files can only be downloaded through authenticated customer/owner routes.
- Random server-side filenames are used.
- Owner can see file counts.
- This is a starter security boundary, not a complete production security audit.

### Stage 4 — Razorpay payments
- Server creates Razorpay Orders.
- Browser receives only the public key ID, order ID and amount.
- Server verifies the returned payment signature.
- Server has a webhook endpoint and validates `X-Razorpay-Signature` with HMAC-SHA256.
- Webhook event IDs are recorded to reduce duplicate processing.
- Payment status changes to Paid after successful verification.
- Test/live secrets belong in environment variables, never source code.

## Before live launch
1. Create a Razorpay account and complete the provider's required onboarding/KYC.
2. Generate TEST API keys and test first.
3. Configure an HTTPS webhook URL in Razorpay Dashboard using a separate webhook secret.
4. Test `order.paid` and signature verification.
5. Only after testing, switch to Live keys.
6. Replace JSON storage with a managed production database.
7. Move private uploads to private object storage with malware scanning and retention rules.
8. Add password reset, email verification, rate limiting, CSRF protection where applicable, audit logging, backups and monitoring.
9. Add privacy policy, terms, refund/cancellation policy and customer consent language.
10. Decide what customer data is actually necessary and keep it to the minimum.
11. Do not accept highly sensitive documents until production storage/security has been reviewed.

## Local test
1. Install Node.js 18+.
2. `npm install`
3. Set environment variables from `ENV.example`.
4. Create an owner using the owner seed procedure from the earlier CivicAssist package, or add an owner record through your deployment process.
5. `npm start`
6. Open `http://localhost:3000`.

Razorpay webhooks cannot target localhost directly; use a public HTTPS staging URL for webhook testing.
