import io
import logging
import tempfile
import subprocess
import base64
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import StreamingResponse
from weasyprint import HTML
from pyhanko.sign.signers import SimpleSigner, PdfSigner
from pyhanko.sign.general import PdfSignatureMetadata
from pyhanko_certvalidator.context import ValidationContext
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()

def normalize_private_key(key_bytes: bytes) -> bytes:
    """
    Detects if the private key is PKCS#1 and converts it into PKCS#8.
    Returns a PKCS#8-compliant key for use in PyHanko.
    """
    try:
        logger.info("🔑 Trying to load private key as PKCS#8...")
        serialization.load_pem_private_key(key_bytes, password=None, backend=default_backend())
        logger.info("✅ Key is already PKCS#8")
        return key_bytes
    except ValueError:
        logger.info("⚠️ Key is not PKCS#8, attempting conversion from PKCS#1 → PKCS#8...")
        with tempfile.NamedTemporaryFile(delete=False) as tmp_in, tempfile.NamedTemporaryFile(delete=False) as tmp_out:
            tmp_in.write(key_bytes)
            tmp_in.flush()
            cmd = [
                "openssl", "pkcs8", "-topk8", "-inform", "PEM", "-outform", "PEM",
                "-in", tmp_in.name, "-out", tmp_out.name, "-nocrypt"
            ]
            subprocess.run(cmd, check=True)
            with open(tmp_out.name, "rb") as f:
                converted_key = f.read()
            logger.info("✅ Conversion to PKCS#8 successful")
            return converted_key

def verify_cert_key_pair(cert: x509.Certificate, private_key) -> bool:
    """
    Verifies that the certificate and private key match.
    """
    try:
        cert_pub = cert.public_key().public_numbers()
        priv_pub = private_key.public_key().public_numbers()
        match = cert_pub.n == priv_pub.n and cert_pub.e == priv_pub.e
        if match:
            logger.info("✅ Certificate and private key match")
        else:
            logger.error("❌ Certificate and private key DO NOT match")
        return match
    except Exception as e:
        logger.error(f"⚠️ Error verifying cert/key pair: {e}")
        return False

@app.post("/pdfs/signed")
async def signed_pdf(
    html_file: UploadFile = File(...),
    cert_file: UploadFile = File(...),
    key_file: UploadFile = File(...),
):
    try:
        logger.info("📄 Step 1: Generating unsigned PDF from HTML")
        html_bytes = await html_file.read()
        pdf_bytes = HTML(string=html_bytes.decode("utf-8")).write_pdf()

        logger.info("🔑 Step 2: Decoding certificate and private key")
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()

        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        key_bytes = normalize_private_key(key_bytes)
        private_key = serialization.load_pem_private_key(
            key_bytes, password=None, backend=default_backend()
        )

        # 🔍 Verify cert/key pair before signing
        verify_cert_key_pair(cert, private_key)

        logger.info("✍️ Step 3: Creating SimpleSigner")
        signer = SimpleSigner(
            signing_cert=cert,
            signing_key=private_key,
            cert_registry=None,
            embed_roots=True,
        )

        logger.info("✍️ Step 4: Signing PDF using PdfSigner")
        meta = PdfSignatureMetadata(
            field_name="Signature1",
            md_algorithm="sha256",  # Force RSA+SHA256
        )
        vc = ValidationContext(allow_fetching=True)

        input_pdf = io.BytesIO(pdf_bytes)
        output_pdf = io.BytesIO()
        pdf_signer = PdfSigner(meta, signer=signer, validation_context=vc)
        pdf_signer.sign_pdf(input_pdf, output_pdf)

        logger.info("✅ PDF signing successful")
        output_pdf.seek(0)
        return StreamingResponse(output_pdf, media_type="application/pdf")

    except Exception as e:
        logger.error(f"❌ Error generating signed PDF:\n{e}", exc_info=True)
        return {"detail": {"error": str(e)}}
