import io
import logging
import tempfile
from datetime import datetime
import pytz
import os

from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

from pyhanko.sign import signers
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.fields import SigFieldSpec
from pyhanko_certvalidator.registry import SimpleCertificateStore
# --- REVERTING TO THE CORRECT IMPORT PATH ---
from pyhanko_certvalidator.pem_parser import parse_pem_certificates

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
    unsigned_pdf_path = ""
    signed_output_path = ""

    try:
        logger.info("📄 Step 1: Converting HTML to PDF")
        html_content = await html_file.read()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
            HTML(string=html_content.decode("utf-8")).write_pdf(tmp_pdf.name)
            unsigned_pdf_path = tmp_pdf.name

        logger.info("🔑 Step 2: Loading certificate and private key")
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()

        cert = parse_pem_certificates(cert_bytes)[0]
        private_key = load_pem_private_key(key_bytes, password=None, backend=default_backend())

        logger.info("✍️ Step 3: Creating signer")
        
        cert_store = SimpleCertificateStore()
        cert_store.register(cert)
        
        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=private_key,
            cert_registry=cert_store
        )
        
        logger.info("🖊 Step 4: Adding metadata + visual stamp")
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
            box=(50, 700, 250, 750),
            page=0
        )

        logger.info("🔏 Step 5: Signing PDF")
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as signed_tmp_file:
            signed_output_path = signed_tmp_file.name
            pdf_signer = PdfSigner(pdf_meta, signer=signer)
            
            with open(unsigned_pdf_path, "rb") as inf:
                pdf_signer.prepare_signing(
                    inf,
                    output_stream=signed_tmp_file,
                    new_field_spec=sig_field_spec
                )
            
            signed_tmp_file.flush()

        logger.info("✅ PDF signed successfully")

        return FileResponse(
            signed_output_path,
            media_type="application/pdf",
            filename="signed_minutes.pdf"
        )

    except Exception as e:
        logger.error("❌ Error signing PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})

    finally:
        if unsigned_pdf_path and os.path.exists(unsigned_pdf_path):
            os.remove(unsigned_pdf_path)
        if signed_output_path and os.path.exists(signed_output_path):
            os.remove(signed_output_path)
