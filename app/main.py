from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from weasyprint import HTML
from starlette.responses import Response

class HTMLPayload(BaseModel):
    html: str

app = FastAPI()

# ✅ Add CORS settings to allow all relevant frontend domains
origins = [
    "http://localhost",
    "http://localhost:3000",
    "https://pulse.dmacq.com",            # Production domain
    "https://dev.dmacq.com",              # Optional dev subdomain
    "https://*.lovableproject.com"        # Wildcard not supported natively, see note below
]

# CORSMiddleware (wildcard manually allowed via allow_origin_regex)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_origin_regex="https://.*\.lovableproject\.com",  # Allows all dev instances
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/pdfs")
async def print_pdf(body: HTMLPayload):
    try:
        byte_string = HTML(string=body.html).write_pdf()
        return Response(content=byte_string, media_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")
