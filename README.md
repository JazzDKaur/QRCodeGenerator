# QRCodeGenerator

Secure, policy-driven Streamlit application that generates QR codes for HTTPS URLs.

## Features
- HTTPS-only URL validation
- Auto-allow secure domains using a configurable allow-list
- Instance/session tracking
- CSV-based audit logging
- In-memory QR code generation (no image persistence)

## Files
- `app.py` – Main Streamlit application
- `allowed_domains.txt` – Domain allow-list (auto-updated)
- `requirements.txt` – Python dependencies

## Run Locally
```bash
pip install -r requirements.txt
streamlit run app.py
