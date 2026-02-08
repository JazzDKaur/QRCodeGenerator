import streamlit as st
import qrcode
from io import BytesIO
from urllib.parse import urlparse
import time
import re
from datetime import datetime
import uuid
import csv
import os

# ======================================================
# CONFIGURATION
# ======================================================
MAX_URL_LENGTH = 2048
MIN_SECONDS_BETWEEN_REQUESTS = 3

DOMAINS_FILE = "allowed_domains.txt"
CSV_LOG_FILE = "instance_audit_log.csv"

URL_REGEX = re.compile(
    r"^https://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$"
)

# ======================================================
# SESSION / INSTANCE INITIALIZATION
# ======================================================
if "instance_id" not in st.session_state:
    st.session_state.instance_id = str(uuid.uuid4())

if "last_request_time" not in st.session_state:
    st.session_state.last_request_time = 0

if "qr_count" not in st.session_state:
    st.session_state.qr_count = 0

# ======================================================
# POLICY UTILITIES
# ======================================================
def extract_root_domain(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def load_allowed_domains():
    domains = set()
    if not os.path.exists(DOMAINS_FILE):
        return domains

    with open(DOMAINS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip().lower()
            if line and not line.startswith("#"):
                domains.add(line)
    return domains


def append_allowed_domain(domain: str):
    with open(DOMAINS_FILE, "a", encoding="utf-8") as f:
        f.write("\n"+ domain )


ALLOWED_DOMAINS = load_allowed_domains()

# ======================================================
# VALIDATION + AUTO-ALLOW LOGIC
# ======================================================
def validate_and_enroll_url(url: str) -> str:
    if not url:
        raise ValueError("URL cannot be empty.")

    if len(url) > MAX_URL_LENGTH:
        raise ValueError("URL exceeds maximum allowed length.")

    if not URL_REGEX.match(url):
        raise ValueError("Invalid URL format.")

    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError("Only HTTPS URLs are allowed.")

    domain = parsed.netloc.lower()
    root_domain = extract_root_domain(domain)

    if not any(domain.endswith(allowed) for allowed in ALLOWED_DOMAINS):
        append_allowed_domain(root_domain)
        ALLOWED_DOMAINS.add(root_domain)

    return url

# ======================================================
# RATE LIMITING
# ======================================================
def rate_limit_check():
    now = time.time()
    if now - st.session_state.last_request_time < MIN_SECONDS_BETWEEN_REQUESTS:
        raise RuntimeError("Too many requests. Please wait.")
    st.session_state.last_request_time = now

# ======================================================
# QR GENERATION
# ======================================================
def generate_qr(data: str) -> BytesIO:
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=10,
        border=4
    )
    qr.add_data(data)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")

    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf

# ======================================================
# CSV INSTANCE LOGGING
# ======================================================
def log_instance_csv(url: str):
    file_exists = os.path.exists(CSV_LOG_FILE)
    parsed = urlparse(url)

    with open(CSV_LOG_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "timestamp_utc",
                "instance_id",
                "event",
                "url",
                "domain",
                "qr_count"
            ])

        writer.writerow([
            datetime.utcnow().isoformat(),
            st.session_state.instance_id,
            "QR_GENERATED",
            url,
            parsed.netloc.lower(),
            st.session_state.qr_count + 1
        ])

# ======================================================
# UI
# ======================================================
st.title("Secure QR Code Generator")

st.caption(f"Instance ID: `{st.session_state.instance_id}`")

url_input = st.text_input(
    "Enter HTTPS URL",
    placeholder="https://claude.ai/public/artifacts/..."
)

if st.button("Generate QR Code", type="primary"):
    try:
        rate_limit_check()
        validated_url = validate_and_enroll_url(url_input)

        qr_buffer = generate_qr(validated_url)
        log_instance_csv(validated_url)

        st.session_state.qr_count += 1

        st.image(qr_buffer, caption="Scan to open the webpage")
        st.markdown(f"### Open Page: [{validated_url}]({validated_url})")

    except ValueError as e:
        st.error(f"Validation failed: {e}")

    except RuntimeError as e:
        st.warning(str(e))

    except Exception:
        st.error("Unexpected error. Operation aborted.")

# ======================================================
# GOVERNANCE / INSTANCE VISIBILITY
# ======================================================
# with st.expander("Instance & Governance Details"):
#   st.write({
 #       "Instance ID": st.session_state.instance_id,
 ##      "Allowed Domains (Current)": sorted(ALLOWED_DOMAINS),
   ##    "CSV Audit File": os.path.abspath(CSV_LOG_FILE)
    #})
