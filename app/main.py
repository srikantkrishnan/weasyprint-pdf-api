import io
import logging
import tempfile
import subprocess
from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML
import pikepdf
from datetime import datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint OpenSSL Signing API")

@app.post("/minutes/signed")
async def sign_minutes(
    html_file: UploadFile,
    cert_file: UploadFile,
    key_file: UploadFile,
    signer_name: str = Form("Secretary"),
    signer_email: str = Form("info@dmacq.com")
):
    try:
        logger.info("📄 Step 1: Generating unsigned PDF from HTML")
        html_content = await html_file.read()
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()

        # Save unsigned PDF
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_pdf:
            HTML(string=html_content.decode("utf-8")).write_pdf(tmp_pdf.name)
            unsigned_pdf_path = tmp_pdf.name

        # Save cert & key to temp files
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as cert_tmp:
            cert_tmp.write(cert_bytes)
            cert_path = cert_tmp.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pem") as key_tmp:
            key_tmp.write(key_bytes)
            key_path = key_tmp.name

        logger.info("🔏 Step 2: Applying OpenSSL digital signature")
        signed_pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name

        # OpenSSL smime signing (binary DER, attach signature inside PDF)
        cmd = [
            "openssl", "smime", "-sign",
            "-binary", "-in", unsigned_pdf_path,
            "-signer", cert_path,
            "-inkey", key_path,
            "-outform", "DER", "-out", signed_pdf_path
        ]
        subprocess.run(cmd, check=True)

        logger.info("🖊️ Step 3: Adding visual signature stamp")
        with pikepdf.open(unsigned_pdf_path) as pdf:
            page = pdf.pages[0]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            note = f"Signed by {signer_name} ({signer_email}) on {timestamp}"

            # Add annotation (visible text stamp)
            page.add_text_annot(
                rect=pikepdf.Rect(50, 50, 400, 100),
                text=note
            )

            pdf.save(signed_pdf_path)

        logger.info("✅ PDF signed successfully")
        return FileResponse(
            signed_pdf_path,
            media_type="application/pdf",
            filename="signed_minutes.pdf"
        )

    except subprocess.CalledProcessError as se:
        logger.error(f"OpenSSL signing failed: {se}")
        return JSONResponse(status_code=500, content={"error": f"OpenSSL signing failed: {str(se)}"})
    except Exception as e:
        logger.error("❌ Error signing PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/")
def root():
    return {"message": "WeasyPrint OpenSSL Signing API is running 🚀"}
