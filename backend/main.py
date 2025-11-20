# main.py
import os
import traceback
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from redactor import redact_file_stream, reload_redaction_store
from utils import sha256_text_iter
from ai_analyzer import analyze_log_with_ai, test_ai_connection, get_all_available_providers
from typing import Dict, Any
import logging
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("log-redactor")

app = FastAPI(title="AI LOG Analysis")


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


CACHE: Dict[str, Any] = {}

SANITIZED_DIR = "sanitized"
os.makedirs(SANITIZED_DIR, exist_ok=True)


@app.on_event("startup")
def startup_event():
    logger.info("Starting redaction service and loading store.")
    reload_redaction_store()
    
    logger.info("=" * 60)
    logger.info("Testing AI Providers...")
    logger.info("=" * 60)
    
    # Get all available providers
    available_providers = get_all_available_providers()
    
    if not available_providers:
        logger.warning("⚠ NO AI PROVIDERS CONFIGURED!")
        logger.warning("⚠ Add DEEPSEEK_API_KEY (recommended), OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY to .env")
        logger.warning("⚠ System will use fallback rule-based analysis")
    else:
        logger.info(f"✓ Found {len(available_providers)} configured provider(s): {', '.join(available_providers)}")
        
        # Test each provider
        for provider in available_providers:
            logger.info(f"Testing {provider}...")
        
        # Test connection (will try all providers in order)
        if test_ai_connection():
            logger.info("✓ AI service connected successfully")
        else:
            logger.warning("⚠ All AI providers failed - check API keys and quotas")
            logger.warning("⚠ System will use fallback rule-based analysis")
    
    logger.info("=" * 60)


@app.get("/")
def health():
    """Health check endpoint"""
    available_providers = get_all_available_providers()
    
    return {
        "status": "ok",
        "message": "Redaction backend with AI analysis running",
        "ai_providers": {
            "available": available_providers,
            "count": len(available_providers),
            "fallback_enabled": True,
            "priority_order": ["deepseek", "openai", "anthropic", "gemini"]
        },
        "cache_size": len(CACHE),
        "sanitized_files": len(os.listdir(SANITIZED_DIR)) if os.path.exists(SANITIZED_DIR) else 0
    }


@app.post("/upload-log")
async def upload_log(file: UploadFile = File(...)):
    """
    Accepts a multipart file upload, redacts it line-by-line,
    writes the FULL sanitized log file, computes hash,
    analyzes with AI, caches results, and returns summary.
    """
    try:
        file_obj = file.file
        file_obj.seek(0)

        logger.info(f"Processing uploaded file: {file.filename}")

        preview, summary, total_bytes = redact_file_stream(file_obj)
        
        logger.info(f"Redaction complete: {summary}")

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

                yield _redactor.redact_line(line, {})  

        hash_value = sha256_text_iter(sanitized_line_generator())
        
        logger.info(f"Computed hash: {hash_value}")

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

        logger.info(f"Sanitized file saved: {sanitized_path}")

        if hash_value in CACHE:
            logger.info(f"Cache hit for hash: {hash_value}")
            return JSONResponse({
                "status": "cached",
                "hash": hash_value,
                "original_filename": file.filename,
                "sanitized_file_path": sanitized_path,
                "total_bytes": total_bytes,
                "preview": preview,
                "redaction_summary": summary,
                "ai_analysis": CACHE[hash_value]
            })

        logger.info(f"Analyzing sanitized file with AI: {sanitized_path}")
        
        try:
            ai_result = analyze_log_with_ai(sanitized_path, file.filename)
            logger.info(f"AI analysis complete: {ai_result.get('issue_type', 'N/A')}")
        except Exception as ai_error:
            logger.error(f"AI analysis failed: {ai_error}")
            ai_result = {
                "issue_type": "AI Analysis Failed",
                "root_cause": "Unable to analyze log file with AI",
                "suggested_fix": "Check AI service configuration and try again",
                "severity": "unknown",
                "error": str(ai_error),
                "analyzed": False
            }

        CACHE[hash_value] = ai_result

        return JSONResponse({
            "status": "new",
            "hash": hash_value,
            "original_filename": file.filename,
            "sanitized_file_path": sanitized_path,
            "total_bytes": total_bytes,
            "preview": preview,
            "redaction_summary": summary,
            "ai_analysis": ai_result
        })

    except Exception as e:
        logger.error(f"Exception in /upload-log: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


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

        logger.info(f"Processing local file: {path}")

        with open(path, "rb") as f:
            preview, summary, total_bytes = redact_file_stream(f)

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

        logger.info(f"Sanitized file saved: {sanitized_path}")

        if hash_value in CACHE:
            logger.info(f"Cache hit for hash: {hash_value}")
            return {
                "status": "cached",
                "path": path,
                "hash": hash_value,
                "sanitized_file_path": sanitized_path,
                "preview": preview,
                "total_bytes": total_bytes,
                "summary": summary,
                "ai_analysis": CACHE[hash_value]
            }

        logger.info(f"Analyzing local file with AI: {sanitized_path}")
        
        try:
            ai_result = analyze_log_with_ai(sanitized_path, os.path.basename(path))
            logger.info(f"AI analysis complete: {ai_result.get('issue_type', 'N/A')}")
        except Exception as ai_error:
            logger.error(f"AI analysis failed: {ai_error}")
            ai_result = {
                "issue_type": "AI Analysis Failed",
                "root_cause": "Unable to analyze log file with AI",
                "suggested_fix": "Check AI service configuration and try again",
                "severity": "unknown",
                "error": str(ai_error),
                "analyzed": False
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
            "ai_analysis": ai_result
        }

    except Exception as e:
        logger.error(f"Error in /upload-local: {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.get("/cache/stats")
def cache_stats():
    """Get cache statistics"""
    return {
        "total_cached_analyses": len(CACHE),
        "cached_hashes": list(CACHE.keys())[:10],
        "sanitized_files_count": len(os.listdir(SANITIZED_DIR)) if os.path.exists(SANITIZED_DIR) else 0
    }


@app.post("/cache/clear")
def clear_cache():
    """Clear the analysis cache (sanitized files remain)"""
    global CACHE
    cache_size = len(CACHE)
    CACHE = {}
    logger.info(f"Cache cleared: {cache_size} entries removed")
    return {
        "status": "success",
        "message": f"Cleared {cache_size} cached analyses"
    }


@app.delete("/sanitized/{hash_value}")
def delete_sanitized_file(hash_value: str):
    """Delete a specific sanitized file and its cache entry"""
    try:
        sanitized_path = os.path.join(SANITIZED_DIR, f"{hash_value}.log")
        
        if not os.path.exists(sanitized_path):
            raise HTTPException(status_code=404, detail="Sanitized file not found")
        
        os.remove(sanitized_path)
        
        if hash_value in CACHE:
            del CACHE[hash_value]
        
        logger.info(f"Deleted sanitized file and cache: {hash_value}")
        
        return {
            "status": "success",
            "message": f"Deleted file and cache for hash: {hash_value}"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting file: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ai/test")
def test_ai():
    """Test AI connection for all providers"""
    try:
        available_providers = get_all_available_providers()
        
        if not available_providers:
            return {
                "status": "no_providers",
                "message": "No AI providers configured. Add DEEPSEEK_API_KEY (recommended), OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY to .env",
                "providers": {
                    "deepseek": {"configured": False, "working": False},
                    "openai": {"configured": False, "working": False},
                    "anthropic": {"configured": False, "working": False},
                    "gemini": {"configured": False, "working": False}
                }
            }
        
        connection_success = test_ai_connection()
        
        from ai_analyzer import deepseek_available, openai_available, anthropic_available, gemini_available
        
        provider_status = {
            "deepseek": {"configured": deepseek_available, "working": None},
            "openai": {"configured": openai_available, "working": None},
            "anthropic": {"configured": anthropic_available, "working": None},
            "gemini": {"configured": gemini_available, "working": None}
        }
        
        # Test DeepSeek
        if deepseek_available:
            try:
                from ai_analyzer import deepseek_client
                response = deepseek_client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[{"role": "user", "content": "test"}],
                    max_tokens=5
                )
                provider_status["deepseek"]["working"] = True
            except Exception as e:
                provider_status["deepseek"]["working"] = False
                provider_status["deepseek"]["error"] = str(e)[:100]
        
        # Test OpenAI
        if openai_available:
            try:
                from ai_analyzer import openai_client
                response = openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": "test"}],
                    max_tokens=5
                )
                provider_status["openai"]["working"] = True
            except Exception as e:
                provider_status["openai"]["working"] = False
                provider_status["openai"]["error"] = str(e)[:100]
        
        # Test Anthropic
        if anthropic_available:
            try:
                from ai_analyzer import anthropic_client
                response = anthropic_client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "test"}]
                )
                provider_status["anthropic"]["working"] = True
            except Exception as e:
                provider_status["anthropic"]["working"] = False
                provider_status["anthropic"]["error"] = str(e)[:100]
        
        # Test Gemini
        if gemini_available:
            try:
                from ai_analyzer import gemini_client
                response = gemini_client.generate_content("test")
                provider_status["gemini"]["working"] = True
            except Exception as e:
                provider_status["gemini"]["working"] = False
                provider_status["gemini"]["error"] = str(e)[:100]
        
        any_working = any(p.get("working") == True for p in provider_status.values())
        
        return {
            "status": "success" if any_working else "all_failed",
            "message": "At least one AI provider is working" if any_working else "All configured AI providers failed",
            "connection_test": connection_success,
            "providers": provider_status,
            "available_providers": available_providers,
            "recommendation": "Add DeepSeek API key for best cost/performance" if not any_working else None
        }
        
    except Exception as e:
        return {
            "status": "error",
            "message": str(e),
            "traceback": traceback.format_exc()
        }


@app.get("/ai/providers")
def get_providers():
    """Get information about configured AI providers"""
    try:
        from ai_analyzer import deepseek_available, openai_available, anthropic_available, gemini_available
        
        available_providers = get_all_available_providers()
        
        return {
            "providers": {
                "deepseek": {
                    "configured": deepseek_available,
                    "name": "DeepSeek",
                    "model": "deepseek-chat",
                    "priority": 1,
                    "cost": "Very Low",
                    "notes": "Best cost/performance ratio"
                },
                "openai": {
                    "configured": openai_available,
                    "name": "OpenAI GPT-4",
                    "model": "gpt-4o-mini",
                    "priority": 2,
                    "cost": "Low-Medium",
                    "notes": "Reliable and fast"
                },
                "anthropic": {
                    "configured": anthropic_available,
                    "name": "Anthropic Claude",
                    "model": "claude-3-5-sonnet",
                    "priority": 3,
                    "cost": "Medium",
                    "notes": "High quality analysis"
                },
                "gemini": {
                    "configured": gemini_available,
                    "name": "Google Gemini",
                    "model": "gemini-1.5-flash",
                    "priority": 4,
                    "cost": "Free tier available",
                    "notes": "Good for testing"
                }
            },
            "active_providers": available_providers,
            "fallback_enabled": True,
            "priority_order": ["deepseek", "openai", "anthropic", "gemini", "fallback"]
        }
    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to get provider information"
        }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)