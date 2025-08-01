import os
import io
import logging
import asyncio
from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from weasyprint import HTML
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers import PdfSignatureMetadata
from datetime import datetime

# Ensure persistent directory
PERSIST_DIR = "/var/data"
os.makedirs(PERSIST_DIR, exist_ok=True)

# Audit log file
AUDIT_LOG_FILE = os.path.join(PERSIST_DIR, "signing_audit.log")

# Configure logging (console + file)
logger = logging.getLogger("main")
logger.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

file_handler = logging.FileHandler(AUDIT_LOG_FILE)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

app = FastAPI(title="dMACQ Minutes Signing API")

CERT_PATH = os.path.join(PERSIST_DIR, "dmacq_signer.pfx")


def embed_names_in_html(html_text, secretary_name, chair_name):
    insert_text = (
        f"<p><strong>Chair: </strong>{chair_name}<br>"
        f"<strong>Secretary: </strong>{secretary_name}</p>\n"
    )
    lowered = html_text.lower()
    if "</body>" in lowered:
        pos = lowered.rfind("</body>")
        html_text = html_text[:pos] + insert_text + html_text[pos:]
    elif "</html>" in lowered:
        pos = lowered.rfind("</html>")
        html_text = html_text[:pos] + insert_text + html_text[pos:]
    else:
        html_text += "\n" + insert_text
    return html_text


@app.on_event("startup")
async def check_cert():
    if not os.path.exists(CERT_PATH):
        logger.warning("⚠️ No PFX certificate found. Upload one via /upload-cert.")
    else:
        logger.info("✅ Certificate found in persistent storage")


@app.post("/upload-cert")
async def upload_cert(pfx_file: UploadFile = File(...), pfx_password: str = Form(...)):
    try:
        with open(CERT_PATH, "wb") as f:
            f.write(await pfx_file.read())
        os.environ["PFX_PASSWORD"] = pfx_password
        msg = "Certificate uploaded successfully"
        logger.info(f"✅ {msg}")
        return {"message": msg}
    except Exception as e:
        error_msg = f"❌ Error uploading certificate: {e}"
        logger.error(error_msg, exc_info=True)
        raise HTTPException(status_code=500, detail=error_msg)


@app.post("/minutes/signed")
async def signed_minutes(
    html_file: UploadFile = File(...),
    secretary_name: str = Form(...),
    chairperson_name: str = Form(...),
):
    return await process_signing(html_text=(await html_file.read()).decode("utf-8"),
                                 secretary_name=secretary_name,
                                 chairperson_name=chairperson_name)


@app.get("/debug/sign")
async def debug_sign():
    """Diagnostic endpoint: sign a static test HTML string"""
    logger.info("🚦 Debug signing test triggered")
    test_html = """
    <html>
    <body>
        <h1>Board Meeting Minutes</h1>
        <p>This is a test document generated for signing diagnostics.</p>
    </body>
    </html>
    """
    return await process_signing(html_text=test_html,
                                 secretary_name="Test Secretary",
                                 chairperson_name="Test Chairperson")


async def process_signing(html_text: str, secretary_name: str, chairperson_name: str):
    temp_pdf_path = os.path.join(PERSIST_DIR, "unsigned_output.pdf")

    try:
        if not os.path.exists(CERT_PATH):
            raise HTTPException(status_code=400, detail="No certificate uploaded. Use /upload-cert first.")
        cert_pass = os.environ.get("PFX_PASSWORD", "").encode()
        if not cert_pass:
            raise HTTPException(status_code=400, detail="Certificate password not set. Please re-upload cert.")

        logger.info("📄 Preparing HTML")
        modified_html = embed_names_in_html(html_text, secretary_name, chairperson_name)

        logger.info("🖨️ Generating PDF with WeasyPrint")
        HTML(string=modified_html).write_pdf(temp_pdf_path)
        logger.info(f"✅ Unsigned PDF written at {temp_pdf_path}")

        logger.info("🔑 Loading signing credentials from PFX")
        signer = signers.SimpleSigner.load_pkcs12(
            pfx_file=CERT_PATH,
            passphrase=cert_pass
        )
        logger.info("✅ Signer loaded successfully")

        logger.info("✍️ Signing PDF using run_in_executor")
        signed_buf = io.BytesIO()

        def blocking_sign():
            with open(temp_pdf_path, "rb") as unsigned_pdf:
                pdf_writer = IncrementalPdfFileWriter(unsigned_pdf)
                signers.sign_pdf(
                    pdf_writer,
                    PdfSignatureMetadata(
                        reason="Digitally signed board minutes",
                        location="dMACQ Software Pvt Ltd, Mumbai, India",
                        contact_info="info@dmacq.com",
                        field_name=None  # Let PyHanko create a new field if needed
                    ),
                    signer=signer,
                    output=signed_buf,
                )
            signed_buf.seek(0)
            return signed_buf

        loop = asyncio.get_event_loop()
        signed_result = await loop.run_in_executor(None, blocking_sign)

        success_msg = f"✅ Signing completed successfully at {datetime.now().isoformat()}"
        logger.info(success_msg)

        return StreamingResponse(
            signed_result,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed_minutes.pdf"},
        )

    except Exception as e:
        error_msg = f"❌ Error in signing pipeline: {e}"
        logger.error(error_msg, exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(temp_pdf_path):
            try:
                os.remove(temp_pdf_path)
                logger.info(f"🗑️ Temp file {temp_pdf_path} deleted")
            except OSError as cleanup_err:
                logger.warning(f"⚠️ Failed to delete temp file: {cleanup_err}")


@app.get("/cert/status")
async def cert_status():
    return {
        "cert_exists": os.path.exists(CERT_PATH),
        "password_set": bool(os.environ.get("PFX_PASSWORD")),
        "audit_log": AUDIT_LOG_FILE,
    }


@app.get("/health")
async def health_check():
    return {"status": "ok"}
