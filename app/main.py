from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import Response
from weasyprint import HTML
from pyhanko.sign import PdfSigner, signers
from pyhanko.sign.fields import SigFieldSpec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import base64
import io
import logging
import pyhanko

# Log PyHanko version for debugging
logging.warning(f"🚀 Using PyHanko version: {pyhanko.__version__}")

class SignPayload(BaseModel):
    html: str
    base_url: str = ""
    certificate_pem: str
    private_key_pem: str
    key_password: str = ""

app = FastAPI()

# Allow all origins for testing; restrict later in production
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
        # Step 1: Generate unsigned PDF from HTML
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Step 2: Decode certificate and key
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)

        # Step 3: Load private key & certificate
        private_key_obj = load_pem_private_key(
            key_bytes,
            password=body.key_password.encode() if body.key_password else None,
            backend=default_backend()
        )
        cert_obj = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        # Step 4: Build a signer
        signer = signers.SimpleSigner(
            signing_cert=cert_obj,
            signing_key=private_key_obj,
            cert_registry=None
        )

        pdf_stream = io.BytesIO(pdf_bytes)
        out = io.BytesIO()

        # Step 5: Use PdfSigner (pyHanko ≥0.20.0)
        pdf_signer = PdfSigner(
            signature_meta=signers.SignatureMeta(field_name="SecretarySignature"),
            signer=signer
        )
        pdf_signer.sign_pdf(pdf_stream, output=out)

        return Response(content=out.getvalue(), media_type="application/pdf")

    except Exception as e:
        logging.error(f"❌ Error generating signed PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {e}")
