import os
import io
import logging
from typing import List
from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from weasyprint import HTML
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers import PdfSignatureMetadata

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI(title="dMACQ Minutes Signing API")


def embed_names_in_html(html_text: str, secretary_name: str, chair_name: str) -> str:
    """Embed secretary and chairperson names into the HTML content."""
    insert_text = (
        f"<p><strong>Chair: </strong>{chair_name}<br>"
        f"<strong>Secretary: </strong>{secretary_name}</p>\n"
    )
    lowered = html_text.lower()
    if "</body>" in lowered:
        pos = lowered.rfind("</body>")
        return html_text[:pos] + insert_text + html_text[pos:]
    elif "</html>" in lowered:
        pos = lowered.rfind("</html>")
        return html_text[:pos] + insert_text + html_text[pos:]
    else:
        return html_text + "\n" + insert_text


@app.post("/minutes/signed")
async def signed_minutes(
    html_file: UploadFile = File(..., description="HTML file for minutes"),
    secretary_name: str = Form(..., description="Secretary's full name"),
    chairperson_name: str = Form(..., description="Chairperson's full name"),
    pfx_file: UploadFile = File(None, description="Upload PKCS#12 (.pfx/.p12) file"),
    pfx_password: str = Form("", description="Password for the PFX file"),
):
    try:
        # Step 1: Read HTML and embed secretary/chair names
        logger.info("📄 Step 1: Preparing HTML")
        html_bytes = await html_file.read()
        html_text = html_bytes.decode("utf-8")
        modified_html = embed_names_in_html(html_text, secretary_name, chairperson_name)

        # Step 2: Generate unsigned PDF on persistent disk
        logger.info("🖨️ Step 2: Generating unsigned PDF")
        temp_pdf_path = "/var/data/unsigned_output.pdf"
        HTML(string=modified_html).write_pdf(temp_pdf_path)

        # Step 3: Load signing credentials
        logger.info("🔑 Step 3: Loading signing credentials")
        signer = None

        if pfx_file:
            pfx_data = await pfx_file.read()
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_data,
                passphrase=pfx_password.encode() if pfx_password else None,
            )
        else:
            raise HTTPException(status_code=400, detail="Either PFX or PEM cert+key must be provided")

        # Step 4: Configure signature metadata
        logger.info("📝 Step 4: Configuring signature metadata")
        signature_meta = PdfSignatureMetadata(
            field_name="Signature",
            reason="Document digitally signed by Company Secretary",
            location="dMACQ Software Private Limited, Mumbai, Maharashtra, India",
            contact_info="info@dmacq.com",
        )

        # Step 5: Apply signature
        logger.info("✍️ Step 5: Signing PDF")
        signed_buf = io.BytesIO()
        with open(temp_pdf_path, "rb") as unsigned_pdf:
            pdf_writer = IncrementalPdfFileWriter(unsigned_pdf)
            signers.sign_pdf(
                pdf_writer,
                signature_meta,
                signer=signer,
                output=signed_buf,
            )

        signed_buf.seek(0)
        return StreamingResponse(
            signed_buf,
            media_type="application/pdf",
            headers={"Content-Disposition": "attachment; filename=signed_minutes.pdf"},
        )

    except Exception as e:
        logger.error(f"❌ Error signing PDF: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        try:
            os.remove(temp_pdf_path)
        except OSError:
            pass
