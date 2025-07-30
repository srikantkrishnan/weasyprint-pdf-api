from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import Response
from weasyprint import HTML
from pyhanko.sign.signers import SimpleSigner
from pyhanko.sign import sign_pdf
from pyhanko.sign.fields import SigFieldSpec
import base64
import io
import logging
import pyhanko

# Log PyHanko version in Render logs
logging.warning(f"🚀 Using PyHanko version: {pyhanko.__version__}")

class SignPayload(BaseModel):
    html: str
    base_url: str = ""
    certificate_pem: str
    private_key_pem: str
    key_password: str = ""

app = FastAPI()

# Allow all origins for testing; restrict later for production
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
        # Generate unsigned PDF
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Decode certificate and key
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)

        # Try with pyhanko<=0.17.2 syntax
        try:
            signer = SimpleSigner.load(
                key_bytes=key_bytes,
                cert_bytes=cert_bytes,
                passphrase=body.key_password.encode() if body.key_password else None,
            )
            logging.warning("✅ Using SimpleSigner.load with key_bytes (pyhanko<=0.17.2)")
        except TypeError:
            logging.warning("⚠️ Falling back to cryptography-based signer (pyhanko>=0.18.0)")
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            from cryptography.hazmat.backends import default_backend
            from cryptography import x509

            private_key_obj = load_pem_private_key(
                key_bytes,
                password=body.key_password.encode() if body.key_password else None,
                backend=default_backend()
            )
            cert_obj = x509.load_pem_x509_certificate(cert_bytes, default_backend())

            signer = SimpleSigner(
                signing_cert=cert_obj,
                signing_key=private_key_obj,
                cert_registry=None
            )

        pdf_stream = io.BytesIO(pdf_bytes)
        out = io.BytesIO()

        # Sign the PDF
        sign_pdf(
            pdf_out=out,
            pdf_in=pdf_stream,
            signer=signer,
            field_spec=SigFieldSpec(sig_field_name="SecretarySignature")
        )

        return Response(content=out.getvalue(), media_type="application/pdf")

    except Exception as e:
        logging.error(f"❌ Error generating signed PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {e}")
