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
from asn1crypto import pem, x509 as asn1_x509

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint Signing API")

CERT_DIR = tempfile.mkdtemp(prefix="certs_")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca.pem")
CA_KEY_FILE = os.path.join(CERT_DIR, "ca.key")
LEAF_CERT_FILE = os.path.join(CERT_DIR, "leaf.pem")
LEAF_KEY_FILE = os.path.join(CERT_DIR, "leaf.key")

CA_VALIDITY_DAYS = 3650
LEAF_VALIDITY_DAYS = 365
RENEW_THRESHOLD_DAYS = 7


# --------------------------
# Certificate helpers
# --------------------------
def generate_ca_and_leaf():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(x509.NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "dMACQ Software Pvt Ltd"),
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
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "dMACQ Software Pvt Ltd"),
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

    for file, data in [
        (CA_CERT_FILE, ca_cert.public_bytes(serialization.Encoding.PEM)),
        (CA_KEY_FILE, ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )),
        (LEAF_CERT_FILE, leaf_cert.public_bytes(serialization.Encoding.PEM)),
        (LEAF_KEY_FILE, leaf_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )),
    ]:
        with open(file, "wb") as f:
            f.write(data)

    logger.info("✅ New CA and leaf certificates generated")


def load_asn1_cert(cert_bytes: bytes):
    if pem.detect(cert_bytes):
        _, _, der_bytes = pem.unarmor(cert_bytes)
    else:
        der_bytes = cert_bytes
    return asn1_x509.Certificate.load(der_bytes)


def check_and_renew_certs():
    try:
        with open(LEAF_CERT_FILE, "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        if leaf_cert.not_valid_after <= datetime.utcnow() + timedelta(days=RENEW_THRESHOLD_DAYS):
            generate_ca_and_leaf()
    except FileNotFoundError:
        generate_ca_and_leaf()


# --------------------------
# API Endpoints
# --------------------------
@app.get("/certs/generate")
def generate_certs():
    generate_ca_and_leaf()
    return {"message": "Certificates generated successfully"}


@app.get("/certs/status")
def cert_status():
    try:
        with open(LEAF_CERT_FILE, "rb") as f:
            leaf_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return {
            "leaf_subject": leaf_cert.subject.rfc4514_string(),
            "leaf_valid_until": leaf_cert.not_valid_after.isoformat(),
            "ca_subject": ca_cert.subject.rfc4514_string(),
            "ca_valid_until": ca_cert.not_valid_after.isoformat(),
        }
    except FileNotFoundError:
        return {"error": "Certificates not found. Run /certs/generate first."}


@app.post("/pdfs/signed")
async def signed_pdf(html_file: UploadFile):
    try:
        check_and_renew_certs()
        html_content = await html_file.read()

        with open(LEAF_CERT_FILE, "rb") as f: leaf_cert_bytes = f.read()
        with open(LEAF_KEY_FILE, "rb") as f: leaf_key_bytes = f.read()
        with open(CA_CERT_FILE, "rb") as f: ca_cert_bytes = f.read()

        # Convert to ASN.1
        leaf_cert_asn1 = load_asn1_cert(leaf_cert_bytes)
        ca_cert_asn1 = load_asn1_cert(ca_cert_bytes)

        leaf_key = serialization.load_pem_private_key(leaf_key_bytes, password=None, backend=default_backend())

        pdf_bytes = HTML(string=html_content.decode("utf-8")).write_pdf()

        cert_store = SimpleCertificateStore()
        cert_store.register(ca_cert_asn1)

        signer = signers.SimpleSigner(
            signing_cert=leaf_cert_asn1,
            signing_key=leaf_key,
            cert_registry=cert_store
        )

        input_buf = io.BytesIO(pdf_bytes)
        output_buf = io.BytesIO()

        pdf_signer = PdfSigner(PdfSignatureMetadata(field_name="Signature1"), signer=signer)
        pdf_signer.sign_pdf(input_buf, output=output_buf)

        output_buf.seek(0)
        return StreamingResponse(
            output_buf,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed.pdf"}
        )

    except SigningError as se:
        return JSONResponse(status_code=500, content={"error": f"Signing failed: {str(se)}"})
    except Exception as e:
        logger.error("❌ PDF signing failed", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/pdfs/self-test")
def pdf_self_test():
    try:
        check_and_renew_certs()
        html_content = "<h1>Signed Hello World 🚀</h1>"
        pdf_bytes = HTML(string=html_content).write_pdf()

        with open(LEAF_CERT_FILE, "rb") as f: leaf_cert_bytes = f.read()
        with open(LEAF_KEY_FILE, "rb") as f: leaf_key_bytes = f.read()
        with open(CA_CERT_FILE, "rb") as f: ca_cert_bytes = f.read()

        leaf_cert_asn1 = load_asn1_cert(leaf_cert_bytes)
        ca_cert_asn1 = load_asn1_cert(ca_cert_bytes)
        leaf_key = serialization.load_pem_private_key(leaf_key_bytes, password=None, backend=default_backend())

        cert_store = SimpleCertificateStore()
        cert_store.register(ca_cert_asn1)

        signer = signers.SimpleSigner(
            signing_cert=leaf_cert_asn1,
            signing_key=leaf_key,
            cert_registry=cert_store
        )

        input_buf = io.BytesIO(pdf_bytes)
        output_buf = io.BytesIO()

        pdf_signer = PdfSigner(PdfSignatureMetadata(field_name="Signature1"), signer=signer)
        pdf_signer.sign_pdf(input_buf, output=output_buf)

        output_buf.seek(0)
        return StreamingResponse(
            output_buf,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=hello-signed.pdf"}
        )

    except Exception as e:
        logger.error("❌ Self-test signing failed", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/")
def root():
    return {"message": "WeasyPrint Signing API is running 🚀"}
