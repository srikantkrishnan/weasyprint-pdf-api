import os
import io
import tempfile
import logging
from typing import List, Optional

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
    pfx_file: Optional[UploadFile] = File(None),
    pfx_password: Optional[str] = Form(""),
    cert_file: Optional[UploadFile] = File(None),
    key_file: Optional[UploadFile] = File(None),
    key_password: Optional[str] = Form(""),
    chain_files: Optional[List[UploadFile]] = File(None),
):
    # Normalize Swagger behavior for optional files
    if chain_files:
        chain_files = [cf for cf in chain_files if getattr(cf, "filename", None)]
        if not chain_files:
            chain_files = None

    try:
        # Step 1: Read HTML and embed secretary & chair names
        logger.info("📄 Step 1: Preparing HTML")
        html_bytes = await html_file.read()
        html_text = html_bytes.decode("utf-8")
        modified_html = embed_names_in_html(html_text, secretary_name, chairperson_name)

        # Step 2: Generate unsigned PDF
        logger.info("🖨️ Step 2: Generating unsigned PDF")
        unsigned_pdf_bytes = HTML(string=modified_html).write_pdf()

        # Step 3: Setup signing credentials
        logger.info("🔑 Step 3: Loading signing credentials")
        signer = None

        if pfx_file:
            pfx_data = await pfx_file.read()
            signer = signers.SimpleSigner.load_pkcs12(
                pfx_data,
                passphrase=pfx_password.encode() if pfx_password else None
            )
        elif cert_file and key_file:
            cert_data = await cert_file.read()
            key_data = await key_file.read()
            chain_data = [await cf.read() for cf in chain_files] if chain_files else []

            # Write cert/key/chain into temp files for PyHanko
            with tempfile.NamedTemporaryFile(delete=False) as cert_tmp, \
                 tempfile.NamedTemporaryFile(delete=False) as key_tmp:
                cert_tmp.write(cert_data)
                key_tmp.write(key_data)
                cert_tmp.flush()
                key_tmp.flush()

                chain_paths = []
                for c in chain_data:
                    with tempfile.NamedTemporaryFile(delete=False) as chain_tmp:
                        chain_tmp.write(c)
                        chain_tmp.flush()
                        chain_paths.append(chain_tmp.name)

                signer = signers.SimpleSigner.load(
                    key_file=key_tmp.name,
                    cert_file=cert_tmp.name,
                    ca_chain_files=chain_paths,
                    key_passphrase=key_password.encode() if key_password else None
                )

                # Cleanup after signer is initialized
                os.unlink(cert_tmp.name)
                os.unlink(key_tmp.name)
                for cp in chain_paths:
                    os.unlink(cp)

        if not signer:
            raise HTTPException(status_code=400, detail="No valid signing credentials provided.")

        # Step 4: Apply digital signature
        logger.info("✍️ Step 4: Signing PDF")
        signature_meta = PdfSignatureMetadata(
            field_name="Signature",
            reason="Document digitally signed by Company Secretary",
            location="dMACQ Software Private Limited, Mumbai, Maharashtra, India",
            contact_info="info@dmacq.com",
        )

        signed_buf = io.BytesIO()
        unsigned_buf = io.BytesIO(unsigned_pdf_bytes)
        pdf_writer = IncrementalPdfFileWriter(unsigned_buf)

        signers.sign_pdf(
            pdf_writer,
            signature_meta,
            signer=signer,
            output=signed_buf
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
