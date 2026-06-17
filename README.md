# Email Health Scanner

A modern email deliverability audit tool built with **Rust + Axum** that analyzes a domain's email infrastructure in real time.

The scanner checks SPF, DMARC, DKIM, MX records, blacklist status, and detects the email provider (Google Workspace, Microsoft 365, Zoho Mail, Proton Mail, Fastmail, Amazon SES, and more).

## Features

* SPF Record Validation
* DMARC Policy Analysis
* DKIM Detection
* MX Record Analysis
* Blacklist Monitoring
* Email Provider Detection
* Domain Deliverability Scoring (A–F)
* Real-Time DNS Checks
* Modern SaaS-Style Dashboard

## Tech Stack

### Backend

* Rust
* Axum
* Tokio
* trust-dns-resolver
* tower-http

### Frontend

* HTML
* CSS
* Vanilla JavaScript

### Deployment

* Render (Backend)
* Netlify (Frontend)

## Project Structure

```text
email-health-scanner/
├── backend/
│   ├── src/main.rs
│   ├── Cargo.toml
│   ├── Dockerfile
│   └── fly.toml
│
└── frontend/
    ├── index.html
    └── _redirects
```

## Running Locally

### Backend

```bash
cd backend
cargo run
```

The API will start on:

```text
http://localhost:3001/api/scan
```

Example Request:

```bash
curl -X POST http://localhost:3001/api/scan \
-H "Content-Type: application/json" \
-d '{"domain":"gmail.com"}'
```

### Frontend

Open:

```text
frontend/index.html
```

in your browser.

Make sure:

```javascript
const API_URL = "http://localhost:3001/api/scan";
```

while testing locally.

## API

### Endpoint

```http
POST /api/scan
```

### Request

```json
{
  "domain": "gmail.com"
}
```

### Response

```json
{
  "domain": "gmail.com",
  "grade": "C",
  "score": 62,
  "summary": "Fair. Score: 62/100.",
  "email_provider": {
    "name": "Google Workspace"
  }
}
```

## Deployment

### Backend (Render)

Push changes to GitHub:

```bash
git add .
git commit -m "Update backend"
git push origin main
```

Render automatically detects the new commit and deploys the latest backend.

### Frontend (Netlify)

Push frontend changes:

```bash
git add .
git commit -m "Update frontend"
git push origin main
```

Netlify automatically deploys the latest frontend build.

## Git Workflow

### Check Changes

```bash
git status
```

### Add Files

```bash
git add .
```

### Commit

```bash
git commit -m "Describe your changes"
```

### Push

```bash
git push origin main
```

### Pull Latest Changes

```bash
git pull origin main
```

## Future Improvements

* PDF Report Export
* Scan History
* DNS Record Explorer
* Security Score Breakdown
* Team Sharing
* Monitoring & Alerts

## Author

Suryateja Malluru

Built using Rust, Axum, and modern web technologies .
