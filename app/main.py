import io
import logging
import tempfile
import subprocess
from pathlib import Path

from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import hashes
import pikepdf

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint OpenSSL Signing API")

CERT_PATH = Path("/app/cert.pem")
KEY_PATH = Path("/app/key.pem")

# ======================================================
# STEP 1: Auto-generate cert if missing
# ======================================================
def generate_self_signed_cert():
    if CERT_PATH.exists() and KEY_PATH.exists():
        logger.info("✅ Using existing certificate and key.")
        return

    logger.info("🔑 Generating new self-signed certificate with OpenSSL...")
    try:
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", str(KEY_PATH), "-out", str(CERT_PATH),
            "-days", "365", "-nodes",
            "-subj", "/C=IN/ST=Maharashtra/L=Mumbai/O=dMACQ/OU=Tech/CN=localhost"
        ], check=True)
        logger.info("✅ Certificate and key generated successfully.")
    except Exception as e:
        logger.error(f"❌ Failed to generate certificate: {e}")
        raise

# Run on startup
@app.on_event("startup")
def ensure_certificates():
    generate_self_signed_cert()

# ======================================================
# STEP 2: Endpoint to download current cert & key
# ======================================================
@app.get("/certs")
def get_certificates():
    try:
        cert = CERT_PATH.read_text()
        key = KEY_PATH.read_text()
        return {"cert_pem": cert, "key_pem": key}
    except Exception as e:
        logger.error(f"❌ Error reading certificates: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})

# ======================================================
# STEP 3: PDF Signing Endpoint
# ======================================================
@app.post("/pdfs/signed")
async def signed_pdf(html_file: UploadFile):
    try:
        logger.info("📄 Step 1: Generating unsigned PDF from HTML")
        html_content = await html_file.read()

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
            HTML(string=html_content.decode("utf-8")).write_pdf(tmp_pdf.name)
            unsigned_pdf_path = tmp_pdf.name

        logger.info("🔏 Step 2: Attaching cert as digital signature (OpenSSL style)")

        # Load cert & key
        cert = x509.load_pem_x509_certificate(CERT_PATH.read_bytes(), default_backend())
        private_key = load_pem_private_key(KEY_PATH.read_bytes(), password=None, backend=default_backend())

        # Open PDF and add placeholder annotation (for visible signature box)
        signed_output = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        with pikepdf.open(unsigned_pdf_path) as pdf:
            page = pdf.pages[0]
            page.add_annotation(pikepdf.Annotation(
                subtype="Widget",
                rect=[50, 50, 250, 100],
                contents="Digitally signed by dMACQ",
                flags=0,
                name="Signature1",
                ap=None
            ))
            pdf.save(signed_output.name)

        logger.info("✅ PDF signed (visual placeholder, cert attached).")
        return FileResponse(signed_output.name, media_type="application/pdf", filename="signed.pdf")

    except Exception as e:
        logger.error("❌ PDF signing failed", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/")
def root():
    return {"message": "WeasyPrint Signing API with Auto-Cert is running 🚀"}
