# Email Health Scanner

Domain deliverability audit tool — checks SPF, DMARC, DKIM, MX records, and blacklists in real time.

## Folder structure

```
email-health-scanner/
├── backend/
│   ├── src/main.rs      ← Rust API server
│   ├── Cargo.toml       ← Rust dependencies
│   ├── Dockerfile       ← Container config
│   └── fly.toml         ← Fly.io deployment config
└── frontend/
    ├── index.html       ← Full scanner UI
    └── _redirects       ← Netlify routing
```

## Step 1 — Run backend locally

```bash
cd backend
cargo run
```

API will be live at: http://localhost:8080/api/scan

Test it:
```bash
curl -X POST http://localhost:8080/api/scan \
  -H "Content-Type: application/json" \
  -d '{"domain":"gmail.com"}'
```

## Step 2 — Open frontend locally

Just open frontend/index.html in your browser.
Change API_URL in index.html to http://localhost:8080/api/scan while testing locally.

## Step 3 — Deploy backend to Fly.io

```bash
# Install flyctl (first time only)
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Inside the backend folder:
cd backend
fly launch --name email-health-scanner --region sin --dockerfile Dockerfile

# Deploy
fly deploy
```

Your API will be live at: https://email-health-scanner.fly.dev

## Step 4 — Deploy frontend to Netlify

1. Change API_URL in frontend/index.html to your Fly.io URL
2. Go to https://app.netlify.com
3. Drag and drop the frontend/ folder
4. Done — get your live URL!

## API

POST /api/scan
Body: { "domain": "example.com" }
Response: { grade, score, domain, summary, checks[] }
