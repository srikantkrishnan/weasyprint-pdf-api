import os
import re
import io
import json
import urllib.parse
import requests
from fastapi import FastAPI, HTTPException, Form
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# FastAPI app
app = FastAPI(title="Teams Recording Fetcher")

# Enable CORS
origins = [
    "https://pulse.dmacq.com",
    "https://*.lovableproject.com",
    "http://localhost:3000",
    "http://localhost:5173"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Persistent recordings folder
RECORDINGS_DIR = "/var/data/recordings"
os.makedirs(RECORDINGS_DIR, exist_ok=True)

GRAPH_SCOPE = "https://graph.microsoft.com/.default"

def get_access_token(tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    data = {
        'client_id': client_id,
        'client_secret': client_secret,
        'scope': GRAPH_SCOPE,
        'grant_type': 'client_credentials'
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(url, data=data, headers=headers)
    response.raise_for_status()
    return response.json().get('access_token')

def extract_thread_id(meeting_url):
    decoded_url = urllib.parse.unquote(meeting_url)
    match = re.search(r'19:meeting_[^@]+@thread\.v2', decoded_url)
    return match.group(0) if match else None

@app.post("/fetch-recording")
def fetch_recording(
    tenant_id: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    meeting_url: str = Form(...)
):
    try:
        # Step 1: Access token
        token = get_access_token(tenant_id, client_id, client_secret)
        if not token:
            raise HTTPException(status_code=401, detail="Unable to obtain access token")

        # Step 2: Extract threadId
        thread_id = extract_thread_id(meeting_url)
        if not thread_id:
            raise HTTPException(status_code=400, detail="Invalid meeting URL: cannot extract threadId")

        # Step 3: Fetch recordings metadata
        url = f"https://graph.microsoft.com/v1.0/me/drive/special/recordings/children"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Step 4: Find matching recording
        recording = None
        for item in data.get("value", []):
            if item.get("source", {}).get("threadId") == thread_id:
                recording = item
                break

        if not recording:
            raise HTTPException(status_code=404, detail="Recording not found for given meeting")

        download_url = recording.get("@microsoft.graph.downloadUrl")
        filename = os.path.join(RECORDINGS_DIR, recording["name"])

        # Step 5: Download MP4 to persistent disk
        with requests.get(download_url, stream=True) as r:
            r.raise_for_status()
            with open(filename, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

        return {
            "status": "success",
            "recording_name": recording["name"],
            "download_url": f"/files/{recording['name']}",
            "metadata": recording
        }

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.get("/files/{filename}")
def serve_file(filename: str):
    filepath = os.path.join(RECORDINGS_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(filepath, media_type="video/mp4", filename=filename)
