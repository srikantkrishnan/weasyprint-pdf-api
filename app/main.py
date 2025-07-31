import io
import logging
import os
import tempfile
from datetime import datetime, timedelta
from fastapi import FastAPI, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from weasyprint import HTML
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.general import SigningError
from pyhanko_certvalidator.registry import SimpleCertificateStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint Signing API")

CERT_DIR = tempfile.mkdtemp(prefix="certs_")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca.pem")
CA_KEY_FILE = os.path.join(CERT_DIR, "ca.key")
LEAF_CERT_FILE = os.path.join(CERT_DIR, "leaf.pem")
LEAF_KEY_FILE = os.path.join(CERT_DIR, "leaf.key")

CA_VALIDITY_DAYS = 3650  # 10 years
LEAF_VALIDITY_DAYS = 365  # 1 year
RENEW_THRESHOLD_DAYS = 7  # renew if expiring soon


def generate_ca_and_leaf():
    """Generate a root CA and leaf certificate, then save them to files."""
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "dMACQ Software"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "dMACQ Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "dMACQ Software"),
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "PDF Signer"),
    ])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_subject)
        .issuer_name(ca_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=LEAF_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )

    with open(CA_CERT_FILE, "wb") as f: f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    with open(CA_KEY_FILE, "wb") as f: f.write(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))
    with open(LEAF_CERT_FILE, "wb") as f: f.write(leaf_cert.public_bytes(serialization.Encoding.PEM))
    with open(LEAF_KEY_FILE, "wb") as f: f.write(leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))

    logger.info(f"✅ Certificates generated and saved in {CERT_DIR}")


def check_and_renew_certs():
    """Check expiry of leaf cert; regenerate if close to expiry."""
    try:
        with open(LEAF_CERT_FILE, "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        expiry = leaf_cert.not_valid_after
        if expiry <= datetime.utcnow() + timedelta(days=RENEW_THRESHOLD_DAYS):
            logger.info(f"⚠️ Leaf cert expiring soon ({expiry}), regenerating...")
            generate_ca_and_leaf()
        else:
            logger.info(f"✅ Leaf certificate valid until {expiry}")
    except FileNotFoundError:
        logger.info("⚠️ No certs found, generating new ones...")
        generate_ca_and_leaf()


@app.get("/certs/generate")
def generate_certs():
    """Manually trigger certificate generation."""
    generate_ca_and_leaf()
    return {"message": "Certificates generated successfully"}


@app.get("/certs/status")
def cert_status():
    """Show the current certificate validity and days remaining."""
    try:
        with open(LEAF_CERT_FILE, "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        leaf_expiry = leaf_cert.not_valid_after
        ca_expiry = ca_cert.not_valid_after
        days_remaining = (leaf_expiry - datetime.utcnow()).days

        return {
            "leaf_cert_valid_from": leaf_cert.not_valid_before.isoformat(),
            "leaf_cert_valid_until": leaf_expiry.isoformat(),
            "leaf_days_remaining": days_remaining,
            "ca_cert_valid_from": ca_cert.not_valid_before.isoformat(),
            "ca_cert_valid_until": ca_expiry.isoformat(),
        }
    except FileNotFoundError:
        return {"error": "Certificates not found. Generate them using /certs/generate."}


@app.post("/pdfs/signed")
async def signed_pdf(html_file: UploadFile):
    """Generate a signed PDF from an uploaded HTML file."""
    try:
        check_and_renew_certs()

        html_content = await html_file.read()
        with open(LEAF_CERT_FILE, "rb") as f: leaf_cert_bytes = f.read()
        with open(LEAF_KEY_FILE, "rb") as f: leaf_key_bytes = f.read()
        with open(CA_CERT_FILE, "rb") as f: ca_cert_bytes = f.read()

        leaf_cert = x509.load_pem_x509_certificate(leaf_cert_bytes, default_backend())
        leaf_key = serialization.load_pem_private_key(leaf_key_bytes, password=None, backend=default_backend())
        ca_cert = x509.load_pem_x509_certificate(ca_cert_bytes, default_backend())

        pdf_bytes = HTML(string=html_content.decode("utf-8")).write_pdf()

        cert_store = SimpleCertificateStore()
        cert_store.register(ca_cert)  # ✅ Correct registry call

        signer = signers.SimpleSigner(
            signing_cert=leaf_cert,
            signing_key=leaf_key,
            cert_registry=cert_store,
            signing_cert_chain=[leaf_cert, ca_cert]
        )

        buffer_in = io.BytesIO(pdf_bytes)
        buffer_out = io.BytesIO()
        pdf_signer = PdfSigner(PdfSignatureMetadata(field_name="Signature1"), signer=signer)
        pdf_signer.sign_pdf(buffer_in, output=buffer_out)

        buffer_out.seek(0)
        return StreamingResponse(
            buffer_out,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed.pdf"}
        )

    except SigningError as se:
        return JSONResponse(status_code=500, content={"error": f"Signing failed: {str(se)}"})
    except Exception as e:
        logger.error("❌ Error generating signed PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/")
def root():
    return {"message": "WeasyPrint Signing API is running 🚀"}
