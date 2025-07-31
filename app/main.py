import subprocess
import tempfile
from fastapi import FastAPI, UploadFile, Form
from fastapi.responses import FileResponse
from weasyprint import HTML
import fitz  # PyMuPDF

app = FastAPI(title="Minutes Signing API (OpenSSL Auto-Cert)")

@app.post("/minutes/signed")
async def sign_minutes(
    html_file: UploadFile,
    secretary_name: str = Form(...),
    chairperson_name: str = Form(...),
    secretary_timestamp: str = Form(...),
    chairperson_timestamp: str = Form(...),
):
    try:
        # Step 1: Convert HTML → PDF
        pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        HTML(file_obj=html_file.file).write_pdf(pdf_path)

        # Step 2: Add Secretary & Chairperson stamps on the LAST PAGE
        doc = fitz.open(pdf_path)
        page = doc[-1]  # last page
        page.insert_text((72, 700), f"Secretary: {secretary_name}", fontsize=11)
        page.insert_text((72, 720), f"Signed at: {secretary_timestamp}", fontsize=9)
        page.insert_text((300, 700), f"Chairperson: {chairperson_name}", fontsize=11)
        page.insert_text((300, 720), f"Signed at: {chairperson_timestamp}", fontsize=9)

        stamped_pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        doc.save(stamped_pdf_path)
        doc.close()

        # Step 3: Generate a fresh OpenSSL certificate + key (auto-expiry 1 year)
        cert_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pem").name
        key_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pem").name
        subj = "/C=IN/ST=Maharashtra/L=Mumbai/O=dMACQ/OU=Tech/CN=DMACQ/emailAddress=info@dmacq.com"

        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048",
            "-keyout", key_path, "-out", cert_path,
            "-days", "365", "-nodes",
            "-subj", subj
        ], check=True)

        # Step 4: Digitally sign PDF using OpenSSL smime
        signed_pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        subprocess.run([
            "openssl", "smime", "-sign",
            "-in", stamped_pdf_path,
            "-signer", cert_path,
            "-inkey", key_path,
            "-outform", "DER",
            "-out", signed_pdf_path,
            "-nodetach"
        ], check=True)

        return FileResponse(
            signed_pdf_path,
            media_type="application/pdf",
            filename="signed_minutes.pdf"
        )

    except Exception as e:
        return {"error": str(e)}

@app.get("/")
def root():
    return {"message": "Minutes Signing API with OpenSSL is running 🚀"}
