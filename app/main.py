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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # ✅ later restrict for prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/pdfs/signed")
async def signed_pdf(body: SignPayload):
    try:
        # Generate unsigned PDF
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Decode cert and key
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)

        # Load signer for pyHanko 0.17.2 (no passphrase arg)
        signer = SimpleSigner.load(
            key_bytes=key_bytes,
            cert_bytes=cert_bytes
        )

        pdf_stream = io.BytesIO(pdf_bytes)
        out = io.BytesIO()

        # Sign the PDF
        sign_pdf(
            pdf_in=pdf_stream,
            pdf_out=out,
            signer=signer,
            field_spec=SigFieldSpec(sig_field_name="SecretarySignature")
        )

        return Response(content=out.getvalue(), media_type="application/pdf")

    except Exception as e:
        logging.error(f"❌ Error generating signed PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {e}")

    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/pdfs/signed")
async def signed_pdf(body: SignPayload):
    try:
        # Generate unsigned PDF
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Decode cert and key into file-like objects
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)

        cert_file = io.BytesIO(cert_bytes)
        key_file = io.BytesIO(key_bytes)

        # PyHanko 0.17.2 expects file-like objects, not raw bytes
        signer = SimpleSigner.load(
            key_file=key_file,
            cert_file=cert_file,
            passphrase=body.key_password.encode() if body.key_password else None,
        )
        logging.warning("✅ Using SimpleSigner.load with key_file and cert_file (pyhanko==0.17.2)")

        # Sign the PDF
        pdf_stream = io.BytesIO(pdf_bytes)
        out = io.BytesIO()

        sign_pdf(
            pdf_out=out,
            pdf_in=pdf_stream,
            signer=signer,
            field_spec=SigFieldSpec(sig_field_name="SecretarySignature")
        )

        logging.warning("✅ PDF signed successfully!")
        return Response(content=out.getvalue(), media_type="application/pdf")

    except Exception as e:
        logging.error(f"❌ Error generating signed PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {e}")

