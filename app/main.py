import io
import logging
import os
import tempfile
from datetime import datetime, timedelta

from fastapi import FastAPI, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from weasyprint import HTML

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from asn1crypto import pem, x509 as asn1_x509
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.general import SigningError
from pyhanko_certvalidator.registry import SimpleCertificateStore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint Signing API")

# Certificate paths
CERT_DIR = tempfile.mkdtemp(prefix="certs_")
CA_CERT_FILE = os.path.join(CERT_DIR, "ca.pem")
CA_KEY_FILE = os.path.join(CERT_DIR, "ca.key")
LEAF_CERT_FILE = os.path.join(CERT_DIR, "leaf.pem")
LEAF_KEY_FILE = os.path.join(CERT_DIR, "leaf.key")

# Validity settings
CA_VALIDITY_DAYS = 3650
LEAF_VALIDITY_DAYS = 365
RENEW_THRESHOLD_DAYS = 7


# ------------------------------------------------
# Certificate Management
# ------------------------------------------------
def generate_ca_and_leaf():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_subject = x509.Name([
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "dMACQ Software Pvt Ltd"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "dMACQ Root CA"),
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
        x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(x509.oid.NameOID.STATE_OR_PROVINCE_NAME, "Maharashtra"),
        x509.NameAttribute(x509.oid.NameOID.ORGANIZATION_NAME, "dMACQ Software Pvt Ltd"),
        x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "PDF Signer"),
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

    # Save certs & keys
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
            logger.info("🔄 Leaf certificate expiring soon, regenerating...")
            generate_ca_and_leaf()
    except FileNotFoundError:
        logger.info("⚠️ No certificates found, generating fresh ones...")
        generate_ca_and_leaf()


# ------------------------------------------------
# Signing Logic
# ------------------------------------------------
async def sign_pdf_bytes(pdf_bytes: bytes, leaf_cert_asn1, leaf_key, ca_cert_asn1):
    cert_store = SimpleCertificateStore()
    cert_store.register(ca_cert_asn1)

    signer = signers.SimpleSigner(
        signing_cert=leaf_cert_asn1,
        signing_key=leaf_key,
        cert_registry=cert_store,
    )

    input_buf = io.BytesIO(pdf_bytes)
    output_buf = io.BytesIO()

    pdf_signer = PdfSigner(PdfSignatureMetadata(field_name="Signature1"), signer=signer)
    await pdf_signer.async_sign_pdf(input_buf, output=output_buf)

    output_buf.seek(0)
    return output_buf


# ------------------------------------------------
# API Endpoints
# ------------------------------------------------
@app.get("/certs/generate")
def generate_certs():
    generate_ca_and_leaf()
    return {"message": "Certificates generated successfully"}


@app.get("/certs/check")
def check_certs():
    results = []
    for cert_file in [CA_CERT_FILE, LEAF_CERT_FILE]:
        try:
            with open(cert_file, "rb") as f:
                cert_bytes = f.read()
            cert = load_asn1_cert(cert_bytes)

            not_after = cert['tbs_certificate']['validity']['not_after'].native
            days_remaining = (not_after - datetime.utcnow()).days

            results.append({
                "file": cert_file,
                "subject": cert.subject.native,
                "issuer": cert.issuer.native,
                "serial": str(cert.serial_number),
                "valid_until": str(not_after),
                "days_remaining": days_remaining,
                "status": "OK" if days_remaining > 0 else "EXPIRED"
            })
        except Exception as e:
            results.append({
                "file": cert_file,
                "error": str(e),
                "status": "FAILED"
            })
    return results


@app.post("/pdfs/signed")
async def signed_pdf(html_file: UploadFile):
    try:
        check_and_renew_certs()
        html_content = await html_file.read()

        with open(LEAF_CERT_FILE, "rb") as f: leaf_cert_bytes = f.read()
        with open(LEAF_KEY_FILE, "rb") as f: leaf_key_bytes = f.read()
        with open(CA_CERT_FILE, "rb") as f: ca_cert_bytes = f.read()

        leaf_cert_asn1 = load_asn1_cert(leaf_cert_bytes)
        ca_cert_asn1 = load_asn1_cert(ca_cert_bytes)
        leaf_key = serialization.load_pem_private_key(leaf_key_bytes, password=None, backend=default_backend())

        pdf_bytes = HTML(string=html_content.decode("utf-8")).write_pdf()
        signed_buf = await sign_pdf_bytes(pdf_bytes, leaf_cert_asn1, leaf_key, ca_cert_asn1)

        return StreamingResponse(
            signed_buf,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed.pdf"}
        )

    except SigningError as se:
        return JSONResponse(status_code=500, content={"error": f"Signing failed: {str(se)}"})
    except Exception as e:
        logger.error("❌ PDF signing failed", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/")
def root():
    return {"message": "WeasyPrint Signing API is running 🚀"}
