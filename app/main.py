import io
import logging
import tempfile
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509

from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.general import SigningError
from pyhanko.sign.fields import SigFieldSpec
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint Signing API")

# -------------------------------------------------------------------
# Utility: Certificate and Key Safety Pre-Check
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# PDF Signing Core
# -------------------------------------------------------------------
async def sign_pdf_bytes(pdf_bytes: bytes, cert, key, ca_cert):
    try:
        logger.info("🔏 Setting up certificate store and signer")
        cert_store = SimpleCertificateStore()
        cert_store.register(ca_cert)  # ✅ properly registers CA cert

        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=key,
            cert_registry=cert_store
        )

        input_buf = io.BytesIO(pdf_bytes)
        reader = PdfFileReader(input_buf)
        writer = IncrementalPdfFileWriter(reader)  # ✅ fixes `.root` issue

        output_buf = io.BytesIO()
        pdf_signer = PdfSigner(PdfSignatureMetadata(field_name="Signature1"), signer=signer)

        logger.info("✍️ Signing PDF asynchronously")
        await pdf_signer.async_sign_pdf(writer, output=output_buf)

        output_buf.seek(0)
        return output_buf
    except Exception as e:
        logger.error("❌ PDF signing failed", exc_info=True)
        raise

# -------------------------------------------------------------------
# API Endpoint: Generate Signed PDF
# -------------------------------------------------------------------
@app.post("/pdfs/signed")
async def signed_pdf(
    html_file: UploadFile,
    cert_file: UploadFile,
    key_file: UploadFile
):
    try:
        logger.info("📄 Step 1: Reading inputs")
        html_content = await html_file.read()
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()

        logger.info("🔑 Step 2: Validating cert/key pair")
        cert, private_key = check_cert_key_match(cert_bytes, key_bytes)

        logger.info("📝 Step 3: Generating unsigned PDF")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
            HTML(string=html_content.decode("utf-8")).write_pdf(tmp_pdf.name)
            unsigned_pdf_path = tmp_pdf.name

        with open(unsigned_pdf_path, "rb") as f:
            pdf_bytes = f.read()

        logger.info("✍️ Step 4: Signing the PDF")
        signed_buf = await sign_pdf_bytes(pdf_bytes, cert, private_key, cert)

        signed_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        signed_file.write(signed_buf.read())
        signed_file.flush()

        logger.info("✅ Step 5: Returning signed PDF")
        return FileResponse(signed_file.name, media_type="application/pdf", filename="signed.pdf")

    except SigningError as se:
        logger.error(f"Signing failed: {se}")
        return JSONResponse(status_code=500, content={"error": f"Signing failed: {str(se)}"})
    except Exception as e:
        logger.error("❌ Error generating signed PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})

# -------------------------------------------------------------------
# Root Check
# -------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "WeasyPrint Signing API is running 🚀"}
