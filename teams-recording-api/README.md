# Teams Recording API

This FastAPI service fetches Microsoft Teams meeting recordings via Microsoft Graph API,
saves the MP4 to Render persistent storage, and returns both metadata and a download URL.

## Endpoints

- **POST /fetch-recording**
  - Inputs: tenant_id, client_id, client_secret, meeting_url
  - Outputs: recording metadata + download URL

- **GET /files/{filename}**
  - Serves the MP4 file stored on persistent disk.

## Deployment Notes

- Mount persistent disk at `/var/data/recordings`
- Ensure CORS is enabled for:
  - https://pulse.dmacq.com
  - https://*.lovableproject.com
  - http://localhost:3000
  - http://localhost:5173
