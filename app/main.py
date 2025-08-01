import os
import io
import logging
from typing import Optional, List
from fastapi import FastAPI, File, Form, UploadFile, HTTPException
from fastapi.responses import StreamingResponse, JSONResponse
from weasyprint import HTML
from pyhanko.sign import signers
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign.signers import PdfSignatureMetadata
from pyhanko_certvalidator.registry import SimpleCertificateStore
from pyhanko.keys import Certificate as PyHankoCertificate

# --- NEW IMPORTS FOR LOW-LEVEL CRYPTOGRAPHY ---
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

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
    html_file: UploadFile = File(..., description="HTML file for minutes"),
    secretary_name: str = Form(..., description="Secretary's full name"),
    chairperson_name: str = Form(..., description="Chairperson's full name"),
    pfx_file: Optional[UploadFile] = File(None, description="Upload PKCS#12 (.pfx/.p12) file containing cert+key"),
    pfx_password: Optional[str] = Form("", description="Password for the PFX file"),
    cert_file: Optional[UploadFile] = File(None, description="Upload PEM certificate file"),
    key_file: Optional[UploadFile] = File(None, description="Upload PEM private key file"),
    key_password: Optional[str] = Form("", description="Password for PEM private key"),
    chain_files: Optional[List[UploadFile]] = File(None, description="Upload one or more PEM CA certificates"),
):
    temp_pdf_path = None
    try:
        # Step 1: Read and modify HTML
        logger.info("📄 Step 1: Preparing HTML")
        html_bytes = await html_file.read()
        html_text = html_bytes.decode("utf-8")
        modified_html = embed_names_in_html(html_text, secretary_name, chairperson_name)

        # Step 2: Generate unsigned PDF
        logger.info("🖨️ Step 2: Generating unsigned PDF")
        with open("unsigned_output.pdf", "wb") as f:
            HTML(string=modified_html).write_pdf(f)
        temp_pdf_path = "unsigned_output.pdf"

        # Step 3: Load signing credentials
        logger.info("🔑 Step 3: Loading signing credentials")
        signer = None

        if pfx_file:
            pfx_data = await pfx_file.read()
            # --- THIS IS THE CORRECT, ROBUST, LOW-LEVEL WAY TO LOAD PFX ---
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                data=pfx_data,
                password=pfx_password.encode() if pfx_password else None,
                backend=default_backend()
            )
            
            # Create a pyhanko-compatible certificate store
            cert_store = SimpleCertificateStore()
            pyhanko_cert = PyHankoCertificate.from_cryptography_certificate(cert)
            cert_store.register(pyhanko_cert)
            
            # Register additional certificates (the chain) if they exist
            if additional_certs:
                for c in additional_certs:
                    cert_store.register(PyHankoCertificate.from_cryptography_certificate(c))
            
            # Create the signer using the loaded objects
            signer = signers.SimpleSigner(
                signing_cert=pyhanko_cert,
                signing_key=private_key,
                cert_registry=cert_store
            )

        elif cert_file and key_file:
            # This logic remains the same as it was already working
            cert_data = await cert_file.read()
            key_data = await key_file.read()
            ca_chain_data = []
            if chain_files:
                for cf in chain_files:
                    if getattr(cf, "filename", None):
                        ca_chain_data.append(await cf.read())

            signer = signers.SimpleSigner.load(
                key_file=io.BytesIO(key_data),
                cert_file=io.BytesIO(cert_data),
                ca_chain_files=[io.BytesIO(c) for c in ca_chain_data] if ca_chain_data else (),
                key_passphrase=key_password.encode() if key_password else None,
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
        if temp_pdf_path and os.path.exists(temp_pdf_path):
            os.remove(temp_pdf_path)
