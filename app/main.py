from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import Response
from weasyprint import HTML
from pyhanko.sign import signers
from pyhanko.sign.general import sign_pdf, PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.fields import SigFieldSpec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import base64
import io
import logging
import pyhanko

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
    allow_origins=["*"],  # restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/pdfs/signed")
async def signed_pdf(body: SignPayload):
    try:
        # Generate unsigned PDF
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Decode PEM inputs
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)

        private_key = load_pem_private_key(
            key_bytes,
            password=body.key_password.encode() if body.key_password else None,
            backend=default_backend()
        )
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        signer = signers.SimpleSigner(
            signing_cert=cert,
            signing_key=private_key,
            cert_registry=None
        )

        pdf_in = io.BytesIO(pdf_bytes)
        pdf_writer = IncrementalPdfFileWriter(pdf_in)
        meta = PdfSignatureMetadata(field_name="SecretarySignature")
        out = sign_pdf(pdf_writer, meta, signer=signer)

        return Response(content=out.getvalue(), media_type="application/pdf")

    except Exception as e:
        logging.error(f"❌ Error generating signed PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {e}")
