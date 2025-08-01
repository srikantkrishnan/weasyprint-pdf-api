import io
import logging
import tempfile
from datetime import datetime
import pytz

from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML
# NOTE: No longer need to import from cryptography for loading certs directly
# from cryptography.hazmat.primitives.serialization import load_pem_private_key
# from cryptography.hazmat.backends import default_backend
# from cryptography import x509

from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko.sign.validation import ValidationContext
from pyhanko.keys import get_pyca_crypto_signer # ADDED: new import to load keys

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="dMACQ Minutes Signing API")

# NOTE: The check_cert_key_match function is now obsolete
# since we're using PyHanko's built-in key loading which handles this internally.
# You can remove this function to clean up the code.
# def check_cert_key_match(cert_pem: bytes, key_pem: bytes):
#     ...

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

        # Step 2: Load certificates and private key using PyHanko helpers
        logger.info("🔑 Step 2: Loading certificate and private key")
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()
        
        # This is the key change: use get_pyca_crypto_signer
        # This function loads the private key and cert, and creates a signer object
        # that is fully compatible with PyHanko's internal workings.
        # It also implicitly validates that the key and cert match.
        signer = get_pyca_crypto_signer(key_bytes, cert_bytes)

        # Step 3: PyHanko handles the certificate store and validation context
        # internally within the signer object, so these steps can be simplified.
        logger.info("✍️ Step 3: Signer created")

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

        # IMPORTANT: Add a box parameter to make the signature visible
        sig_field_spec = SigFieldSpec(
            sig_field_name="dMACQ_Signature",
            box=(50, 700, 250, 750), # Example coordinates: (x1, y1, x2, y2)
            page=0 # Page number (0-indexed)
        )

        # Step 5: Sign PDF
        logger.info("🔏 Step 5: Signing PDF")
        signed_output = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        
        # Use the prepare_signing method for a more modern API
        # The signer object already contains the cert and key
        with open(unsigned_pdf_path, "rb") as inf:
            # We now pass the pre-built signer object directly to PdfSigner
            pdf_signer = PdfSigner(pdf_meta, signer=signer)
            pdf_signer.prepare_signing(
                inf,
                output_stream=signed_output,
                new_field_spec=sig_field_spec
            )
            # Make sure to flush the buffer before returning the file
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
