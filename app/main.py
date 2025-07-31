import io
import logging
import os
import subprocess
import tempfile
from fastapi import FastAPI, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from weasyprint import HTML
import pikepdf

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="WeasyPrint + OpenSSL Visible PDF Signing API")

# -------------------------------------------------------------------
# Utility: Create placeholder signature field
# -------------------------------------------------------------------
def add_signature_field(input_pdf_path: str, output_pdf_path: str):
    """Add a visible signature field to the PDF so Adobe shows signature status."""
    with pikepdf.open(input_pdf_path) as pdf:
        # Add an AcroForm dictionary if not present
        if "/AcroForm" not in pdf.Root:
            pdf.Root.AcroForm = pdf.make_indirect(pikepdf.Dictionary(
                Fields=[]
            ))

        # Create a widget annotation for signature
        sig_field = pikepdf.Dictionary(
            Type="/Annot",
            Subtype="/Widget",
            FT="/Sig",
            T="Signature1",
            Rect=[50, 700, 250, 750],  # Position on page (x1,y1,x2,y2)
            V=None,
            F=4,
            P=pdf.pages[0]
        )

        # Attach field to the page
        pdf.pages[0].Annots.append(pdf.make_indirect(sig_field))
        pdf.Root.AcroForm.Fields.append(pdf.make_indirect(sig_field))

        pdf.save(output_pdf_path)

# -------------------------------------------------------------------
# Endpoint: Generate signed PDF
# -------------------------------------------------------------------
@app.post("/pdfs/signed")
async def signed_pdf(
    html_file: UploadFile,
    cert_file: UploadFile,
    key_file: UploadFile
):
    try:
        logger.info("📄 Step 1: Reading inputs")
        html_content = await html_file.read()
        cert_bytes = await cert_file.read()
        key_bytes = await key_file.read()

        # Create temp files
        unsigned_pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as signed_placeholder:
            placeholder_pdf_path = signed_placeholder.name
        signed_pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
        cert_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pem").name
        key_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pem").name

        # Save cert & key
        with open(cert_path, "wb") as f:
            f.write(cert_bytes)
        with open(key_path, "wb") as f:
            f.write(key_bytes)

        logger.info("📄 Step 2: Generating unsigned PDF")
        HTML(string=html_content.decode("utf-8")).write_pdf(unsigned_pdf_path)

        logger.info("🖊️ Step 3: Adding visible signature placeholder")
        add_signature_field(unsigned_pdf_path, placeholder_pdf_path)

        logger.info("✍️ Step 4: Signing PDF with OpenSSL CMS")
        # Sign using detached PKCS#7
        cms_path = tempfile.NamedTemporaryFile(delete=False, suffix=".p7s").name
        cmd = [
            "openssl", "smime", "-sign",
            "-binary", "-in", placeholder_pdf_path,
            "-signer", cert_path,
            "-inkey", key_path,
            "-outform", "DER", "-out", cms_path
        ]
        subprocess.run(cmd, check=True)

        # For now, embed PKCS#7 as an attachment
        with pikepdf.open(placeholder_pdf_path) as pdf:
            with open(cms_path, "rb") as cms_file:
                cms_data = cms_file.read()
            ef_dict = pikepdf.Dictionary()
            ef_dict.Type = "/EmbeddedFile"
            ef_dict.Subtype = "/application/pkcs7-signature"
            stream = pdf.make_stream(cms_data)
            stream.Type = "/EmbeddedFile"
            filespec = pikepdf.Dictionary(
                Type="/Filespec",
                F="signature.p7s",
                EF=pikepdf.Dictionary(F=stream)
            )
            pdf.Root.EmbeddedFiles = pdf.make_indirect(
                pikepdf.Dictionary(Names=["signature.p7s", filespec])
            )
            pdf.save(signed_pdf_path)

        logger.info("✅ PDF signed and embedded successfully with visible field")
        return FileResponse(signed_pdf_path, media_type="application/pdf", filename="signed.pdf")

    except subprocess.CalledProcessError as e:
        logger.error(f"OpenSSL signing failed: {e}")
        return JSONResponse(status_code=500, content={"error": f"OpenSSL signing failed: {str(e)}"})
    except Exception as e:
        logger.error("❌ Error generating signed PDF", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})

# -------------------------------------------------------------------
# Root health check
# -------------------------------------------------------------------
@app.get("/")
def root():
    return {"message": "WeasyPrint + OpenSSL Visible PDF Signing API is running 🚀"}
