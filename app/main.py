import os
import io
import logging
from typing import List

from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from weasyprint import HTML
from pyhanko.sign import signers
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI(title="dMACQ Minutes Signing API")

def embed_names_in_html(html_text, secretary_name, chair_name):
    """Embed secretary and chairperson names into the HTML content."""
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

@app.post("/minutes/signed")
async def signed_minutes(
    html_file: UploadFile = File(...),
    secretary_name: str = Form(...),
    chairperson_name: str = Form(...),
    pfx_file: UploadFile = File(None),
    pfx_password: str = Form(""),
    cert_file: UploadFile = File(None),
    key_file: UploadFile = File(None),
    key_password: str = Form(""),
    chain_files: List[UploadFile] = File(None)
):
    try:
        # ✅ Normalize empty Swagger behavior for chain_files
        if chain_files:
            chain_files = [cf for cf in chain_files if getattr(cf, "filename", None)]
            if not chain_files:  # if only empty values came through
                chain_files = None

        # Step 1: Read HTML and embed names
        logger.info("📄 Step 1: Preparing HTML")
        html_bytes = await html_file.read()
        html_text = html_bytes.decode("utf-8")
        modified_html = embed_names_in_html(html_text, secretary_name, chairperson_name)

        # Step 2: Generate unsigned PDF in memory
        logger.info("🖨️ Step 2: Generating unsigned PDF")
        unsigned_buf = io.BytesIO()
        HTML(string=modified_html).write_pdf(unsigned_buf)
        unsigned_buf.seek(0)

        # Step 3: Load signing credentials
        logger.info("🔑 Step 3: Loading signing credentials")
        signer = None
        if pfx_file:
            pfx_data = await pfx_file.read()
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_file=io.BytesIO(pfx_data),
                passphrase=pfx_password.encode() if pfx_password else None
            )
        elif cert_file and key_file:
            cert_data = await cert_file.read()
            key_data = await key_file.read()
            ca_chain_data = []
            if chain_files:
                for cf in chain_files:
                    ca_chain_data.append(await cf.read())
            signer = signers.SimpleSigner.load(
                key_file=io.BytesIO(key_data),
                cert_file=io.BytesIO(cert_data),
                ca_chain_files=[io.BytesIO(c) for c in ca_chain_data],
                key_passphrase=key_password.encode() if key_password else None
            )
        else:
            raise HTTPException(status_code=400, detail="No signing credentials provided")

        # Step 4: Configure metadata
        signature_meta = PdfSignatureMetadata(
            field_name="Signature",
            reason="Document digitally signed by Company Secretary",
            location="dMACQ Software Private Limited, Mumbai, Maharashtra, India",
            contact_info="info@dmacq.com"
        )

        # Step 5: Apply signature
        logger.info("✍️ Step 4: Signing PDF")
        signed_buf = io.BytesIO()
        pdf_writer = IncrementalPdfFileWriter(unsigned_buf)
        signers.sign_pdf(
            pdf_writer,
            signature_meta,
            signer=signer,
            output=signed_buf
        )

        signed_buf.seek(0)
        return StreamingResponse(signed_buf, media_type="application/pdf", headers={
            "Content-Disposition": "attachment; filename=signed_minutes.pdf"
        })

    except Exception as e:
        logger.error(f"❌ Error signing PDF: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": str(e)})
