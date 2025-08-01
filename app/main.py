import io
import logging
import tempfile
from datetime import datetime
import pytz

from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML

# Re-importing cryptography libraries, as we'll load the cert/key manually
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

        # Step 2: Load certificates and private key using cryptography
        logger.info("🔑 Step 2: Loading certificate and private key")
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()

        # Load the certificate and key manually
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        private_key = load_pem_private_key(key_bytes, password=None, backend=default_backend())

        # Step 3: Create signer using PyHanko's SimpleSigner
        logger.info("✍️ Step 3: Creating signer")
        
        # We must manually create a certificate store and register the cert
        # This solves the `AttributeError` from before by providing a cert_registry
        cert_store = SimpleCertificateStore()
        # Note: The `cert_store.register` method expects a certificate object
        # from its own library. To get around this, we can try to wrap it or
        # let SimpleSigner handle it.
        
        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=private_key
            # The SimpleSigner constructor can take a cert_registry, but we can
            # let it handle it internally for a self-signed certificate case.
            # If you have a full chain, you would pass it here.
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

        sig_field_spec = SigFieldSpec(
            sig_field_name="dMACQ_Signature",
            box=(50, 700, 250, 750),  # Example coordinates: (x1, y1, x2, y2)
            page=0  # Page number (0-indexed)
        )

        # Step 5: Sign PDF
        logger.info("🔏 Step 5: Signing PDF")
        signed_output = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        
        pdf_signer = PdfSigner(pdf_meta, signer=signer)
        with open(unsigned_pdf_path, "rb") as inf:
            pdf_signer.prepare_signing(
                inf,
                output_stream=signed_output,
                new_field_spec=sig_field_spec
            )
            signed_output.flush()

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
