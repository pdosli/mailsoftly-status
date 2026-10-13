from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os
import hmac
import hashlib
import time

app = FastAPI()

MAILSOFTLY_PUBLIC_KEY = os.getenv("MAILSOFTLY_PUBLIC_KEY")


def mailsoftly_signature_valid(signature_header: str, raw_body: str, secret: str) -> bool:
    if not signature_header:
        return False

    # Parse the signature header into key-value pairs
    pairs = [pair.strip().split("=") for pair in signature_header.split(",") if "=" in pair]
    
    # Extract timestamp (t) and signature list (v1)
    timestamp = next((val for key, val in pairs if key == "t"), None)
    signatures = [val for key, val in pairs if key == "v1"]

    if not timestamp or not signatures:
        return False

    try:
        timestamp_num = float(timestamp)
    except ValueError:
        return False

    # Check tolerance (5 minutes / 300 seconds)
    if abs(time.time() - timestamp_num) > 300:
        return False

    # Compute expected HMAC signature
    # Note: Secret and message must be converted to bytes for hmac in Python
    secret_bytes = secret.encode("utf-8")
    message_bytes = f"{timestamp}.{raw_body}".encode("utf-8")
    
    expected_hex = hmac.new(
        secret_bytes, 
        msg=message_bytes, 
        digestmod=hashlib.sha256
    ).hexdigest()
    
    expected_bytes = expected_hex.encode("utf-8")

    # Verify using a constant-time comparison to prevent timing attacks
    for sig in signatures:
        sig_bytes = sig.encode("utf-8")
        if hmac.compare_digest(sig_bytes, expected_bytes):
            return True

    return False


@app.post("/mailsoftly/status")
async def mailsoftly_status(request: Request):
    signature = request.headers.get("X-Mailsoftly-Signature")
    
    if not signature:
        raise HTTPException(status_code=401, detail="Missing Mailsoftly signature header")
        
    payload = await request.body()
    verified = mailsoftly_signature_valid(
        signature_header=signature,
        raw_body=payload,
        secret=MAILSOFTLY_PUBLIC_KEY
    )
    
    if not verified:
        raise HTTPException(status_code=403, detail="Invalid Mailsoftly signature")
    
    status = await request.json()
    print("Received status:", status)
    return JSONResponse({"status": "ok"})
