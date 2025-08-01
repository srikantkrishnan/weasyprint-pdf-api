import io
import logging
import tempfile
from datetime import datetime
import pytz

from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko.sign.validation import ValidationContext

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="dMACQ Minutes Signing API")


# Validate certificate + private key match
def check_cert_key_match(cert_pem: bytes, key_pem: bytes):
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    key = load_pem_private_key(key_pem, password=None, backend=default_backend())
    try:
        cert.public_key().public_numbers()
        key.public_key().public_numbers()
    except Exception as e:
        raise ValueError("Certificate and private key mismatch") from e
    return cert, key


@app.post("/minutes/signed")
async def signed_minutes(
    html_file: UploadFile,
    cert_file: UploadFile,
    key_file: UploadFile,
    secretary_name: str = Form(...),
    chairperson_name: str = Form(...)
):
    try:
        # Step 1: Convert HTML to PDF
        logger.info("📄 Step 1: Converting HTML to PDF")
        html_content = await html_file.read()
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
            HTML(string=html_content.decode("utf-8")).write_pdf(tmp_pdf.name)
            unsigned_pdf_path = tmp_pdf.name

        # Step 2: Load certificates
        logger.info("🔑 Step 2: Validating certificate and private key")
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()
        cert, private_key = check_cert_key_match(cert_bytes, key_bytes)

        # Prepare certificate store
        cert_store = SimpleCertificateStore()
        cert_store.register(cert)
        validation_context = ValidationContext(trust_roots=cert_store)

        # Step 3: Create signer
        logger.info("✍️ Step 3: Creating signer")
        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=private_key,
            cert_registry=cert_store
        )

        # Step 4: Add metadata + visual stamp
        logger.info("🖊 Step 4: Adding metadata + stamp")
        ist = pytz.timezone("Asia/Kolkata")
        timestamp = datetime.now(ist).strftime("%d %B %Y, %I:%M %p IST")

        pdf_meta = PdfSignatureMetadata(
            field_name="dMACQ_Signature",
            reason=f"Minutes signed by Secretary {secretary_name} and Chairperson {chairperson_name}",
            location="Mumbai, India",
            contact_info="info@dmacq.com",
        )

        sig_field_spec = SigFieldSpec(sig_field_name="dMACQ_Signature")

        # Step 5: Sign PDF
        logger.info("🔏 Step 5: Signing PDF")
        signed_output = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")

        pdf_signer = PdfSigner(pdf_meta, signer=signer, new_field_spec=sig_field_spec)
        with open(unsigned_pdf_path, "rb") as inf:
            pdf_signer.sign_pdf(inf, output=signed_output)

        logger.info("✅ PDF signed successfully")

        return FileResponse(
            signed_output.name,
            media_type="application/pdf",
            filename="signed_minutes.pdf"
        )

    except Exception as e:
        logger.error("❌ Error signing PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})


@app.get("/")
def root():
    return {"message": "dMACQ Minutes Signing API is running 🚀"}
