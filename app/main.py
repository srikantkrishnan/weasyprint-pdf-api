from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import Response
from weasyprint import HTML
from pyhanko.sign.signers import SimpleSigner
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.signers.pdf_signer import PdfSigner, PdfSignatureMetadata
from pyhanko.sign.general import load_cert_from_pemder  # ✅ NEW import
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
import base64
import io
import logging
import traceback
import pyhanko

logging.basicConfig(level=logging.INFO)
logging.warning(f"🚀 Using PyHanko version: {pyhanko.__version__}")

class SignPayload(BaseModel):
    html: str
    base_url: str = ""
    certificate_pem: str
    private_key_pem: str
    key_password: str = ""

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/pdfs/signed")
async def signed_pdf(body: SignPayload):
    try:
        logging.info("📄 Step 1: Generating unsigned PDF from HTML")
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        logging.info("🔑 Step 2: Decoding certificate and private key")
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)

        private_key_obj = load_pem_private_key(
            key_bytes,
            password=body.key_password.encode() if body.key_password else None,
            backend=default_backend()
        )

        # ✅ FIX: use pyhanko loader instead of cryptography.x509
        cert_obj = load_cert_from_pemder(cert_bytes)

        logging.info("✍️ Step 3: Creating SimpleSigner")
        signer = SimpleSigner(
            signing_cert=cert_obj,
            signing_key=private_key_obj,
            cert_registry=None  # skip chain validation for now
        )

        logging.info("✍️ Step 4: Signing PDF using PdfSigner")
        pdf_stream = io.BytesIO(pdf_bytes)
        out = io.BytesIO()

        pdf_signer = PdfSigner(
            signature_meta=PdfSignatureMetadata(field_name="SecretarySignature"),
            signer=signer,
            new_field_spec=SigFieldSpec(sig_field_name="SecretarySignature")
        )

        pdf_signer.sign_pdf(pdf_stream, out)

        logging.info("✅ Successfully signed PDF")
        return Response(content=out.getvalue(), media_type="application/pdf")

    except Exception as e:
        tb_str = traceback.format_exc()
        logging.error("❌ Error generating signed PDF:\n" + tb_str)
        raise HTTPException(status_code=500, detail={
            "error": str(e),
            "traceback": tb_str
        })
