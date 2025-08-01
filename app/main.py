import logging
import tempfile
import asyncio
from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import JSONResponse, FileResponse
from weasyprint import HTML
from pyhanko.sign import signers
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.general import load_cert_from_pemder
from pyhanko.sign.validation import ValidationContext
from pyhanko_certvalidator import CertificateValidator, ValidationContext as CertValidationContext
from asn1crypto import pem

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI()

# File paths for cert & key
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"


# --------- Certificate Loader with asn1crypto Fallback --------- #
def load_certificate(path: str):
    with open(path, "rb") as f:
        cert_bytes = f.read()
    if pem.detect(cert_bytes):
        logger.info("PEM detected, using asn1crypto unarmor.")
        _, _, der_bytes = pem.unarmor(cert_bytes)
        return load_cert_from_pemder(der_bytes)
    else:
        logger.info("DER detected, loading directly.")
        return load_cert_from_pemder(cert_bytes)


@app.post("/minutes/signed")
async def signed_minutes(
    html_file: UploadFile,
    secretary_name: str = Form(...),
    chairperson_name: str = Form(...),
):
    try:
        logger.info("📄 Step 1: Generate base PDF from HTML")
        html_bytes = await html_file.read()

        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
            HTML(string=html_bytes.decode("utf-8")).write_pdf(tmp_pdf.name)
            unsigned_pdf_path = tmp_pdf.name

        logger.info("🔑 Step 2: Load certificate and private key")
        cert = load_certificate(CERT_FILE)
        with open(KEY_FILE, "rb") as f:
            key_bytes = f.read()

        # Create validation context
        cert_validator = CertificateValidator(cert)
        cert_validator.validate(ValidationContext(trust_roots=[cert]))

        logger.info("✍️ Step 3: Create signer with Adobe-compatible settings")
        signer = signers.SimpleSigner.load(
            signing_cert=CERT_FILE,
            signing_key=KEY_FILE,
            cert_registry=None,
            prefer_pss=False,  # RSA PKCS#1 v1.5 for Adobe compatibility
        )

        # Add visible signature field to the PDF
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as signed_pdf:
            sig_field_spec = SigFieldSpec(sig_field_name="dMACQ-Signature")
            pdf_signer = signers.PdfSigner(
                signers.PdfSignatureMetadata(
                    field_name="dMACQ-Signature",
                    reason=f"Approved by Secretary {secretary_name} and Chairperson {chairperson_name}",
                    location="Mumbai, India",
                    contact_info="info@dmacq.com",
                ),
                signer=signer,
                new_field_spec=sig_field_spec,
            )

            logger.info("🔏 Step 4: Signing PDF using pyHanko")
            await pdf_signer.async_sign_pdf(
                input_path=unsigned_pdf_path, output=signed_pdf.name
            )

            logger.info("✅ Signing complete")
            return FileResponse(
                signed_pdf.name,
                media_type="application/pdf",
                filename="signed_minutes.pdf",
            )

    except Exception as e:
        logger.error("❌ Error signing PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})
