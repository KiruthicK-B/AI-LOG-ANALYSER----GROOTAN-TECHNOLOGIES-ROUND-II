# main.py
import os
import traceback
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from redactor import redact_file_stream, reload_redaction_store
from utils import sha256_text_iter
from typing import Dict, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("log-redactor")

app = FastAPI(title="Regex Redaction Engine")

# Allow your frontend origin here if needed
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Simple in-memory cache for demonstration (replace with DB)
CACHE: Dict[str, Any] = {}

# Directory where sanitized files will be stored
SANITIZED_DIR = "sanitized"
os.makedirs(SANITIZED_DIR, exist_ok=True)


@app.on_event("startup")
def startup_event():
    logger.info("Starting redaction service and loading store.")
    reload_redaction_store()


@app.get("/")
def health():
    return {"status": "ok", "message": "Redaction backend running"}


@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):
    """
    Accepts a multipart file upload, redacts it line-by-line,
    writes the FULL sanitized log file, computes hash,
    caches analysis result, and returns summary.
    """
    try:
        file_obj = file.file
        file_obj.seek(0)

        # ----------------------------------------
        # 1️⃣ STREAM & REDACT (Preview Only)
        # ----------------------------------------
        preview, summary, total_bytes = redact_file_stream(file_obj)

        # ----------------------------------------
        # 2️⃣ RERUN REDACTION FOR HASH + SAVED FILE
        # ----------------------------------------
        file_obj.seek(0)

        from redactor import _redactor

        def sanitized_line_generator():
            """Stream sanitized lines for hashing + saving."""
            file_obj.seek(0)
            for raw in file_obj:
                try:
                    line = raw.decode("utf-8", errors="ignore")
                except:
                    line = str(raw)

                yield _redactor.redact_line(line, {})  # sanitize line

        # Compute deterministic SHA-256 from sanitized content
        hash_value = sha256_text_iter(sanitized_line_generator())

        # ----------------------------------------
        # 3️⃣ SAVE FULL SANITIZED LOG FILE
        # ----------------------------------------
        sanitized_path = os.path.join(SANITIZED_DIR, f"{hash_value}.log")

        file_obj.seek(0)
        with open(sanitized_path, "w", encoding="utf-8") as out_file:
            for raw in file_obj:
                try:
                    line = raw.decode("utf-8", errors="ignore")
                except:
                    line = str(raw)

                sanitized_line = _redactor.redact_line(line, {})
                out_file.write(sanitized_line)

        # ----------------------------------------
        # 4️⃣ CACHE CHECK
        # ----------------------------------------
        if hash_value in CACHE:
            return JSONResponse({
                "status": "cached",
                "hash": hash_value,
                "sanitized_file_path": sanitized_path,
                "total_bytes": total_bytes,
                "preview": preview,
                "redaction_summary": summary,
                "analysis": CACHE[hash_value]
            })

        # ----------------------------------------
        # 5️⃣ PLACEHOLDER FOR AI (YOU WILL ADD LATER)
        # ----------------------------------------
        ai_result = {
            "issue_type": "not_analyzed",
            "root_cause": "AI not integrated yet",
            "suggested_fix": "Integrate AI later",
            "severity": "unknown"
        }

        CACHE[hash_value] = ai_result

        return JSONResponse({
            "status": "new",
            "hash": hash_value,
            "sanitized_file_path": sanitized_path,
            "total_bytes": total_bytes,
            "preview": preview,
            "redaction_summary": summary,
            "analysis": ai_result
        })

    except Exception as e:
        logger.error(f"Exception in /upload-log: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error while processing upload")


@app.post("/upload-local")
async def upload_local(payload: Dict[str, str]):
    """
    Test-only endpoint for reading a local file path.
    Do NOT use in production.
    """
    try:
        path = payload.get("path")
        if not path:
            raise HTTPException(status_code=400, detail="Missing 'path' in payload")
        if not os.path.isabs(path):
            raise HTTPException(status_code=400, detail="Provide absolute file path")
        if not os.path.exists(path):
            raise HTTPException(status_code=404, detail="File not found")

        # Stream file → preview
        with open(path, "rb") as f:
            preview, summary, total_bytes = redact_file_stream(f)

        # Generate sanitized hash + write file
        with open(path, "rb") as f2:
            from redactor import _redactor

            def sanitized_gen_local():
                for raw in f2:
                    try:
                        line = raw.decode("utf-8", errors="ignore")
                    except:
                        line = str(raw)
                    yield _redactor.redact_line(line, {})

            hash_value = sha256_text_iter(sanitized_gen_local())

        sanitized_path = os.path.join(SANITIZED_DIR, f"{hash_value}.log")

        with open(path, "rb") as f3, open(sanitized_path, "w", encoding="utf-8") as out:
            for raw in f3:
                try:
                    line = raw.decode("utf-8", errors="ignore")
                except:
                    line = str(raw)
                out.write(_redactor.redact_line(line, {}))

        if hash_value in CACHE:
            return {
                "status": "cached",
                "path": path,
                "hash": hash_value,
                "sanitized_file_path": sanitized_path,
                "preview": preview,
                "total_bytes": total_bytes,
                "summary": summary,
                "analysis": CACHE[hash_value]
            }

        ai_result = {
            "status": "not_analyzed",
            "message": "AI not integrated"
        }
        CACHE[hash_value] = ai_result

        return {
            "status": "new",
            "path": path,
            "hash": hash_value,
            "sanitized_file_path": sanitized_path,
            "preview": preview,
            "total_bytes": total_bytes,
            "summary": summary,
            "analysis": ai_result
        }

    except Exception as e:
        logger.error(f"Error in /upload-local: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal server error")
