from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi.responses import Response
from weasyprint import HTML, CSS
from io import BytesIO

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

class HTMLPayload(BaseModel):
    html: str
    base_url: str = ""

# 📄 Custom WeasyPrint CSS for clean layout and ToC support
CUSTOM_CSS = """
@page {
  size: A4;
  margin: 15mm;
}

body, html {
  line-height: 1.4;
  font-size: 11pt;
  widows: 2;
  orphans: 2;
}

h1, h2, h3 {
  margin-top: 12px;
  margin-bottom: 8px;
  page-break-after: avoid;
}

table, section, div, ul, ol {
  page-break-inside: avoid;
  break-inside: avoid;
}

.toc, .table-of-contents {
  margin-bottom: 10px;
  padding-left: 0;
}

thead {
  display: table-header-group;
}

tr, td, th {
  page-break-inside: avoid;
}
"""

@app.post("/pdfs")
async def print_pdf(body: HTMLPayload):
    try:
        pdf = HTML(string=body.html, base_url=body.base_url).write_pdf(
            stylesheets=[CSS(string=CUSTOM_CSS)]
        )
        return Response(content=pdf, media_type="application/pdf")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")
