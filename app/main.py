from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from weasyprint import HTML
import io
from fastapi.responses import StreamingResponse
from pyhanko.sign import signers
from pyhanko_certvalidator.context import ValidationContext

app = FastAPI()

# ✅ Add CORS for Lovable + your domain
origins = [
    "http://localhost",
    "http://localhost:3000",
    "https://pulse.dmacq.com",      # PROD domain
    "https://*.lovableproject.com", # DEV domains
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class PrintPdfRequest(BaseModel):
    html: str
    base_url: str = ""
    certificate_pem: str
    private_key_pem: str
    key_password: str | None = None  # optional, in case key is encrypted

@app.post("/pdfs/signed")
async def print_signed_pdf(body: PrintPdfRequest):
    try:
        # Step 1: Generate PDF from HTML
        pdf_bytes = HTML(string=body.html, base_url=body.base_url).write_pdf()

        # Step 2: Load signing credentials
        signer = signers.SimpleSigner.load(
            key_data=body.private_key_pem.encode(),
            cert_data=body.certificate_pem.encode(),
            key_passphrase=(body.key_password.encode() if body.key_password else None)
        )

        # Step 3: Apply digital signature
        vc = ValidationContext(allow_fetching=True)
        signed_pdf = signers.sign_pdf(
            io.BytesIO(pdf_bytes),
            signers.PdfSigner(
                signers.PdfSignatureMetadata(field_name="Signature1"),
                signer=signer,
                validation_context=vc
            )
        )

        # Step 4: Return signed PDF
        return StreamingResponse(
            io.BytesIO(signed_pdf.getbuffer()),
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed_minutes.pdf"}
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating signed PDF: {str(e)}")
