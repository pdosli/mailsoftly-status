from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import os
import hmac
import hashlib
import time

app = FastAPI()

MAILSOFTLY_PUBLIC_KEY = os.getenv("MAILSOFTLY_PUBLIC_KEY")


def mailsoftly_signature_valid(signature_header: str, raw_body: bytes, secret: str) -> bool:
    if not signature_header:
        print("[Mailsoftly] Verification failed: X-Mailsoftly-Signature header is empty or missing.")
        return False

    # Parse the signature header into key-value pairs
    pairs = [pair.strip().split("=") for pair in signature_header.split(",") if "=" in pair]
    
    # Extract timestamp (t) and signature list (v1)
    timestamp = next((val for key, val in pairs if key == "t"), None)
    signatures = [val for key, val in pairs if key == "v1"]

    if not timestamp:
        print(f"[Mailsoftly] Verification failed: Timestamp ('t') not found. Header: {signature_header}")
        return False
        
    if not signatures:
        print(f"[Mailsoftly] Verification failed: No signatures ('v1') found. Header: {signature_header}")
        return False

    try:
        timestamp_num = float(timestamp)
    except ValueError:
        print(f"[Mailsoftly] Verification failed: Timestamp ('t') is not a valid number. Found: '{timestamp}'")
        return False

    # Check tolerance (5 minutes / 300 seconds)
    current_time = time.time()
    time_drift = abs(current_time - timestamp_num)
    if time_drift > 300:
        print(
            f"[Mailsoftly] Verification failed: Clock drift too high. "
            f"Server time: {current_time}, Header timestamp: {timestamp_num} (Drift: {time_drift:.2f}s, Max allowed: 300s)"
        )
        return False

    # Compute expected HMAC signature
    # Note: Secret and message must be converted to bytes for hmac in Python
    timestamp_bytes = timestamp.encode("utf-8")
    secret_bytes = secret.encode("utf-8")
    message_bytes = timestamp_bytes + b"." + raw_body
    
    expected_hex = hmac.new(
        secret_bytes, 
        msg=message_bytes, 
        digestmod=hashlib.sha256
    ).hexdigest()
    
    expected_bytes = expected_hex.encode("utf-8")
    
    print(f"[Mailsoftly] Expected signature computed: {expected_hex}")
    print(f"[Mailsoftly] Number of signatures in header to check: {len(signatures)}")

    # Verify using a constant-time comparison to prevent timing attacks
    for i, sig in enumerate(signatures):
        sig_bytes = sig.encode("utf-8")
        if hmac.compare_digest(sig_bytes, expected_bytes):
            print("[Mailsoftly] Verification succeeded: Signature matched successfully!")
            return True
        else:
            print(f"[Mailsoftly] Signature index {i} did not match. Provided: {sig}")

    print("[Mailsoftly] Verification failed: None of the provided 'v1' signatures matched the computed hash.")
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
