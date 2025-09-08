#!/usr/bin/env python3
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import requests, os, asyncio
from datetime import datetime, timedelta

app = FastAPI(title="VirusTotalService", version="1.1")

# ----- Load API key -----
VIRUSTOTAL_API_KEY = "d902757ed7506de13ae9cb14d8edbaf9ba1d681b71885d7d4e533ee6164da606"
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# ----- Request model -----
class VTRequest(BaseModel):
    target: str = Field(..., description="IP address or URL to investigate")
    confirm: bool = Field(False, description="Must be true to authorize query")

# ----- Global state for rate limiting -----
last_request_time = None
REQUEST_INTERVAL = timedelta(minutes=2)

# ----- Endpoints -----
@app.post("/virustotal")
async def virustotal_lookup(req: VTRequest):
    global last_request_time

    if not req.confirm:
        raise HTTPException(status_code=400, detail="Set confirm=true to authorize VirusTotal query.")

    if not VIRUSTOTAL_API_KEY:
        raise HTTPException(status_code=500, detail="Missing VirusTotal API key")

    now = datetime.utcnow()
    # Nếu request trước đó chưa quá 2 phút, chờ
    if last_request_time and now - last_request_time < REQUEST_INTERVAL:
        wait_time = (REQUEST_INTERVAL - (now - last_request_time)).total_seconds()
        await asyncio.sleep(wait_time)

    # Cập nhật timestamp lần request mới
    last_request_time = datetime.utcnow()

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    started = datetime.utcnow().isoformat() + "Z"

    try:
        if req.target.startswith("http://") or req.target.startswith("https://"):
            # URL scan
            vt_url = f"{VT_BASE_URL}/urls"
            resp = requests.post(vt_url, headers=headers, data={"url": req.target})
            resp.raise_for_status()
            scan_id = resp.json().get("data", {}).get("id")
            if not scan_id:
                raise HTTPException(status_code=500, detail="Failed to get scan ID from VirusTotal")
            # Get report
            report_resp = requests.get(f"{VT_BASE_URL}/analyses/{scan_id}", headers=headers)
            report_resp.raise_for_status()
            result = report_resp.json()
        else:
            # IP lookup
            vt_url = f"{VT_BASE_URL}/ip_addresses/{req.target}"
            resp = requests.get(vt_url, headers=headers)
            resp.raise_for_status()
            result = resp.json()
    except requests.RequestException as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {
        "target": req.target,
        "queried_at": started,
        "virustotal_data": result
    }

@app.get("/health")
def health():
    return {"status": "ok", "virustotal_api_key_set": bool(VIRUSTOTAL_API_KEY)}
