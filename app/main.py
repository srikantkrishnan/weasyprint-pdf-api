from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from weasyprint import HTML
from starlette.responses import Response
from pyhanko.sign import signers
import base64
import io

class SignedPDFPayload(BaseModel):
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
async def print_signed_pdf(body: SignedPDFPayload):
    try:
        # Generate PDF from HTML
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Decode Base64 certificate & key
        cert_bytes = base64.b64decode(body.certificate_pem)
        key_bytes = base64.b64decode(body.private_key_pem)
        password = body.key_password.encode() if body.key_password else None

        # Create a SimpleSigner
        signer = signers.SimpleSigner.load(
            cert_bytes,
            key_bytes,
            passphrase=password
        )

        # Sign the PDF
        pdf_out = io.BytesIO()
        pdf_out.write(
            signers.sign_pdf(
                io.BytesIO(pdf_bytes),
                signer=signer,
                sign_kwargs={"reason": "Approved Board Minutes"}
            )
        )
        pdf_out.seek(0)

        return Response(
            content=pdf_out.read(),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed_minutes.pdf"}
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {e}")
