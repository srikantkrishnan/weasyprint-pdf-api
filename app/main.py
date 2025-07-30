from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from starlette.responses import Response
from weasyprint import HTML
from pyhanko.sign.signers import SimpleSigner
from pyhanko.sign.fields import SigFieldSpec
from pyhanko.sign.general import PdfSigner, PdfSignatureMetadata
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend
from cryptography import x509
import base64
import io
import logging
import pyhanko
from pyhanko_certvalidator import CertificateValidator, ValidationContext

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
    allow_origins=["*"],  # tighten later in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/pdfs/signed")
async def signed_pdf(body: SignPayload):
    try:
        # Step 1: Generate unsigned PDF
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Step 2: Decode cert + key
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)

        private_key_obj = load_pem_private_key(
            key_bytes,
            password=body.key_password.encode() if body.key_password else None,
            backend=default_backend()
        )
        cert_obj = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        # Step 3: Wrap cert in PyHanko's expected validator context
        vc = ValidationContext()
        validator = CertificateValidator(cert_obj, validation_context=vc)
        pyhanko_cert = validator.validate_usage(set())

        signer = SimpleSigner(
            signing_cert=pyhanko_cert,
            signing_key=private_key_obj,
            cert_registry=None
        )

        # Step 4: Use PdfSigner
        pdf_stream = io.BytesIO(pdf_bytes)
        out = io.BytesIO()

        pdf_signer = PdfSigner(
            signature_meta=PdfSignatureMetadata(field_name="SecretarySignature"),
            signer=signer,
            new_field_spec=SigFieldSpec(sig_field_name="SecretarySignature")
        )

        pdf_signer.sign_pdf(pdf_stream, out)

        return Response(content=out.getvalue(), media_type="application/pdf")

    except Exception as e:
        logging.exception("❌ Error generating signed PDF:")
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {e}")
