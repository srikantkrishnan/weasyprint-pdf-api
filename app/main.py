import io
import logging
import tempfile
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from weasyprint import HTML
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.general import SigningError

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint Signing API")

# Safety pre-check function
def check_cert_key_match(cert_pem: bytes, key_pem: bytes):
    try:
        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        key = load_pem_private_key(key_pem, password=None, backend=default_backend())

        cert_pub = cert.public_key().public_numbers()
        key_pub = key.public_key().public_numbers()

        if cert_pub.n != key_pub.n or cert_pub.e != key_pub.e:
            raise ValueError("Certificate and private key do NOT match.")
        
        logger.info("✅ Certificate and private key match confirmed.")
        return cert, key

    except Exception as e:
        logger.error(f"❌ Cert/Key validation failed: {e}")
        raise

@app.post("/pdfs/signed")
async def signed_pdf(
    html_file: UploadFile,
    cert_file: UploadFile,
    key_file: UploadFile
):
    try:
        logger.info("📄 Step 1: Generating unsigned PDF from HTML")
        html_content = await html_file.read()
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()

        # Safety check
        logger.info("🔑 Step 2: Validating certificate and private key")
        cert, private_key = check_cert_key_match(cert_bytes, key_bytes)

        # Generate unsigned PDF in memory
        pdf_bytes = HTML(string=html_content.decode("utf-8")).write_pdf()

        logger.info("✍️ Step 3: Creating SimpleSigner (skip cert registry)")
        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=private_key,
            cert_registry=None,          # ✅ Avoid issuer_serial error
            validation_context=None,     # ✅ Skip validation for now
            signature_mechanism=signers.SignatureMechanism.RSASSA_PKCS1v15(hashes.SHA256())
        )

        logger.info("✍️ Step 4: Signing PDF in memory")
        buffer_in = io.BytesIO(pdf_bytes)
        buffer_out = io.BytesIO()

        pdf_signer = PdfSigner(PdfSignatureMetadata(field_name="Signature1"), signer=signer)
        pdf_signer.sign_pdf(buffer_in, output=buffer_out)

        buffer_out.seek(0)
        logger.info("✅ PDF signing completed successfully")
        return StreamingResponse(
            buffer_out, 
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed.pdf"}
        )

    except SigningError as se:
        logger.error(f"Signing failed: {se}")
        return JSONResponse(status_code=500, content={"error": f"Signing failed: {str(se)}"})
    except Exception as e:
        logger.error("❌ Error generating signed PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/")
def root():
    return {"message": "WeasyPrint Signing API is running 🚀"}
