from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from weasyprint import HTML
from starlette.responses import Response

class HTMLPayload(BaseModel):
    html: str

app = FastAPI()

# Allow only your Lovable app domain — replace if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://3c765d59-016f-4d50-bdcc-20491cc9a7e6.lovableproject.com"
    ],
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
