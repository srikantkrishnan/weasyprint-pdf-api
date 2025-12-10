from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from weasyprint import HTML
from starlette.responses import StreamingResponse
import io

class HTMLPayload(BaseModel):
    htmlContent: str  # ← Changed from 'html' to match frontend
    title: str = "Document"

app = FastAPI()

# ✅ CORS settings
origins = [
    "http://localhost",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://localhost:8080",
    "https://pulse.dmacq.com",
    "https://dev.dmacq.com",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # ← NOW USING THE LIST!
    allow_origin_regex=r"https://.*\.lovableproject\.com",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)

# ✅ Health endpoint - matches frontend's /health call
@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "weasyprint-pdf-generator"}

# ✅ PDF generation endpoint - matches frontend's /generate-pdf-blob call
@app.post("/generate-pdf-blob")
async def generate_pdf_blob(body: HTMLPayload):
    try:
        byte_string = HTML(string=body.htmlContent).write_pdf()
        pdf_stream = io.BytesIO(byte_string)

        headers = {
            "Content-Disposition": f'attachment; filename="{body.title}.pdf"'
        }

        return StreamingResponse(
            pdf_stream,
            media_type="application/pdf",
            headers=headers
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")

# ✅ Keep legacy /pdfs endpoints for backward compatibility
@app.post("/pdfs")
async def print_pdf_legacy(body: HTMLPayload):
    return await generate_pdf_blob(body)

@app.get("/pdfs")
def check_service_legacy():
    return {"status": "WeasyPrint PDF service is up!"}
