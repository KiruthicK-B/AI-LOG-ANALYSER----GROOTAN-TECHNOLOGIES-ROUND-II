# ai_analyzer.py - Multi-provider support with DeepSeek, Gemini, OpenAI, Anthropic
import os
import json
import logging
from typing import Dict, Optional
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("ai_analyzer")

# Try to import different AI providers
openai_available = False
anthropic_available = False
gemini_available = False
deepseek_available = False

try:
    from openai import OpenAI
    openai_client = None
    api_key = os.getenv("OPENAI_API_KEY")
    if api_key:
        openai_client = OpenAI(api_key=api_key)
        openai_available = True
        logger.info("OpenAI client initialized")
except Exception as e:
    logger.warning(f"OpenAI not available: {e}")

try:
    import anthropic
    anthropic_client = None
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        anthropic_client = anthropic.Anthropic(api_key=api_key)
        anthropic_available = True
        logger.info("Anthropic client initialized")
except Exception as e:
    logger.warning(f"Anthropic not available: {e}")

try:
    import google.generativeai as genai
    gemini_client = None
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key:
        genai.configure(api_key=api_key)
        gemini_client = genai.GenerativeModel('gemini-1.5-flash')
        gemini_available = True
        logger.info("Gemini client initialized")
except Exception as e:
    logger.warning(f"Gemini not available: {e}")

# DeepSeek uses OpenAI-compatible API
try:
    from openai import OpenAI
    deepseek_client = None
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if api_key:
        deepseek_client = OpenAI(
            api_key=api_key,
            base_url="https://api.deepseek.com"
        )
        deepseek_available = True
        logger.info("DeepSeek client initialized")
except Exception as e:
    logger.warning(f"DeepSeek not available: {e}")


def get_available_provider() -> str:
    """Determine which AI provider is available (priority order)"""
    providers = []
    
    if deepseek_available:
        providers.append("deepseek")
    if openai_available:
        providers.append("openai")
    if anthropic_available:
        providers.append("anthropic")
    if gemini_available:
        providers.append("gemini")
    
    if not providers:
        return "none"
    
    return providers[0]


def get_all_available_providers() -> list:
    """Get list of all available providers"""
    providers = []
    if deepseek_available:
        providers.append("deepseek")
    if openai_available:
        providers.append("openai")
    if anthropic_available:
        providers.append("anthropic")
    if gemini_available:
        providers.append("gemini")
    return providers


def test_ai_connection() -> bool:
    """Test if any AI service is accessible - tries all providers in order"""
    providers = get_all_available_providers()
    
    if not providers:
        logger.error("No AI provider available")
        return False
    
    # Try each provider until one works
    for provider in providers:
        try:
            if provider == "deepseek":
                response = deepseek_client.chat.completions.create(
                    model="deepseek-chat",
                    messages=[{"role": "user", "content": "test"}],
                    max_tokens=5
                )
                logger.info("✓ DeepSeek connection successful")
                return True
            
            elif provider == "openai":
                response = openai_client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": "test"}],
                    max_tokens=5
                )
                logger.info("✓ OpenAI connection successful")
                return True
            
            elif provider == "anthropic":
                response = anthropic_client.messages.create(
                    model="claude-3-5-sonnet-20241022",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "test"}]
                )
                logger.info("✓ Anthropic Claude connection successful")
                return True
            
            elif provider == "gemini":
                response = gemini_client.generate_content("test")
                logger.info("✓ Google Gemini connection successful")
                return True
        
        except Exception as e:
            logger.warning(f"✗ {provider} test failed: {str(e)[:80]}")
            continue
    
    logger.error("All AI providers failed connection test")
    return False


def read_log_file_intelligently(file_path: str, max_chars: int = 50000) -> str:
    """
    Read log file intelligently - get beginning, middle, and end samples
    to stay within token limits while providing representative content
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if len(content) <= max_chars:
            return content
        
        # Sample from beginning, middle, and end
        chunk_size = max_chars // 3
        
        beginning = content[:chunk_size]
        middle_start = (len(content) - chunk_size) // 2
        middle = content[middle_start:middle_start + chunk_size]
        end = content[-chunk_size:]
        
        sampled_content = (
            "=== LOG FILE BEGINNING ===\n"
            f"{beginning}\n\n"
            "=== LOG FILE MIDDLE SECTION ===\n"
            f"{middle}\n\n"
            "=== LOG FILE END ===\n"
            f"{end}\n\n"
            f"[Note: This is a sampled view. Total file size: {len(content)} characters]"
        )
        
        return sampled_content
    
    except Exception as e:
        logger.error(f"Error reading log file: {e}")
        raise


def create_analysis_prompt(log_content: str, filename: str) -> str:
    """Create the prompt for AI analysis"""
    
    prompt = f"""You are an expert log file analyzer. Analyze the following sanitized log file and provide a detailed technical analysis.

**Log File:** {filename}

**Log Content:**
```
{log_content}
```

**Analysis Requirements:**
Provide a comprehensive analysis in the following JSON format:

{{
  "issue_type": "string - Primary category of issues found (e.g., 'Authentication Errors', 'Database Connection Failures', 'Memory Leaks', 'API Errors', 'Configuration Issues', 'Performance Degradation', 'Security Vulnerabilities', 'Network Issues', 'No Critical Issues')",
  
  "root_cause": "string - Detailed explanation of the underlying cause of the issues. Be specific and reference log patterns you observed.",
  
  "suggested_fix": "string - Actionable, specific recommendations to resolve the issues. Include code snippets, configuration changes, or steps to take.",
  
  "severity": "string - One of: 'critical', 'high', 'medium', 'low', or 'info'",
  
  "error_patterns": [
    "string - List of specific error messages or patterns found"
  ],
  
  "affected_components": [
    "string - List of system components or services affected"
  ],
  
  "timeline_analysis": "string - Brief description of when issues started and their progression if discernible from timestamps",
  
  "additional_recommendations": [
    "string - List of proactive measures or best practices"
  ],
  
  "confidence_level": "string - Your confidence in this analysis: 'high', 'medium', or 'low'",
  
  "summary": "string - A concise 2-3 sentence summary of the entire analysis"
}}

**Important Guidelines:**
1. Be specific and actionable - avoid generic advice
2. Reference actual patterns from the log when possible
3. If no critical issues found, still provide value through optimization suggestions
4. Consider both immediate fixes and long-term improvements
5. Assess severity based on potential business impact
6. Return ONLY valid JSON, no additional text or markdown formatting
"""
    
    return prompt


def analyze_with_deepseek(log_content: str, filename: str) -> Dict:
    """Analyze using DeepSeek"""
    if not deepseek_client:
        raise Exception("DeepSeek client not initialized")
    
    prompt = create_analysis_prompt(log_content, filename)
    
    response = deepseek_client.chat.completions.create(
        model="deepseek-chat",
        messages=[
            {
                "role": "system",
                "content": "You are an expert log file analyzer with deep knowledge of system administration, debugging, and troubleshooting. Analyze logs thoroughly and provide actionable insights."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3,
        max_tokens=2000,
        response_format={"type": "json_object"}
    )
    
    result = json.loads(response.choices[0].message.content)
    result["ai_provider"] = "deepseek"
    result["ai_model"] = "deepseek-chat"
    result["tokens_used"] = {
        "prompt": response.usage.prompt_tokens,
        "completion": response.usage.completion_tokens,
        "total": response.usage.total_tokens
    }
    
    return result


def analyze_with_openai(log_content: str, filename: str) -> Dict:
    """Analyze using OpenAI GPT"""
    if not openai_client:
        raise Exception("OpenAI client not initialized")
    
    prompt = create_analysis_prompt(log_content, filename)
    
    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": "You are an expert log file analyzer with deep knowledge of system administration, debugging, and troubleshooting. Analyze logs thoroughly and provide actionable insights."
            },
            {
                "role": "user",
                "content": prompt
            }
        ],
        temperature=0.3,
        max_tokens=2000,
        response_format={"type": "json_object"}
    )
    
    result = json.loads(response.choices[0].message.content)
    result["ai_provider"] = "openai"
    result["ai_model"] = "gpt-4o-mini"
    result["tokens_used"] = {
        "prompt": response.usage.prompt_tokens,
        "completion": response.usage.completion_tokens,
        "total": response.usage.total_tokens
    }
    
    return result


def analyze_with_anthropic(log_content: str, filename: str) -> Dict:
    """Analyze using Anthropic Claude"""
    if not anthropic_client:
        raise Exception("Anthropic client not initialized")
    
    prompt = create_analysis_prompt(log_content, filename)
    
    response = anthropic_client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=2000,
        temperature=0.3,
        system="You are an expert log file analyzer with deep knowledge of system administration, debugging, and troubleshooting. Analyze logs thoroughly and provide actionable insights. Always respond with valid JSON.",
        messages=[
            {
                "role": "user",
                "content": prompt
            }
        ]
    )
    
    # Extract JSON from response
    response_text = response.content[0].text
    
    # Claude might wrap JSON in markdown, so let's clean it
    if "```json" in response_text:
        response_text = response_text.split("```json")[1].split("```")[0].strip()
    elif "```" in response_text:
        response_text = response_text.split("```")[1].split("```")[0].strip()
    
    result = json.loads(response_text)
    result["ai_provider"] = "anthropic"
    result["ai_model"] = "claude-3-5-sonnet"
    result["tokens_used"] = {
        "input": response.usage.input_tokens,
        "output": response.usage.output_tokens,
        "total": response.usage.input_tokens + response.usage.output_tokens
    }
    
    return result


def analyze_with_gemini(log_content: str, filename: str) -> Dict:
    """Analyze using Google Gemini"""
    if not gemini_client:
        raise Exception("Gemini client not initialized")
    
    prompt = create_analysis_prompt(log_content, filename)
    
    # Configure generation parameters
    generation_config = {
        "temperature": 0.3,
        "top_p": 0.95,
        "top_k": 40,
        "max_output_tokens": 2000,
    }
    
    # Add system instruction for JSON output
    full_prompt = (
        "You are an expert log file analyzer with deep knowledge of system administration, "
        "debugging, and troubleshooting. Analyze logs thoroughly and provide actionable insights. "
        "Always respond with valid JSON only, no markdown formatting.\n\n"
        f"{prompt}"
    )
    
    response = gemini_client.generate_content(
        full_prompt,
        generation_config=generation_config
    )
    
    # Extract JSON from response
    response_text = response.text
    
    # Gemini might wrap JSON in markdown, so let's clean it
    if "```json" in response_text:
        response_text = response_text.split("```json")[1].split("```")[0].strip()
    elif "```" in response_text:
        response_text = response_text.split("```")[1].split("```")[0].strip()
    
    result = json.loads(response_text)
    result["ai_provider"] = "gemini"
    result["ai_model"] = "gemini-1.5-flash"
    result["tokens_used"] = {
        "note": "Token counting not available for Gemini API"
    }
    
    return result


def get_fallback_analysis(log_content: str, filename: str) -> Dict:
    """Provide basic rule-based analysis when AI is unavailable"""
    logger.warning("Using fallback analysis - no AI provider available")
    
    lines = log_content.split('\n')
    
    # Count error patterns
    errors = [line for line in lines if 'ERROR' in line.upper()]
    warnings = [line for line in lines if 'WARNING' in line.upper()]
    exceptions = [line for line in lines if 'Exception' in line]
    
    # Detect common issues
    issues = []
    severity = "info"
    
    if any('Connection' in line and 'refused' in line for line in errors):
        issues.append("Database/Network connection failures detected")
        severity = "high"
    
    if any('Authentication' in line and 'failed' in line for line in errors):
        issues.append("Authentication failures detected")
        severity = "medium"
    
    if any('OutOfMemory' in line for line in exceptions):
        issues.append("Memory issues detected")
        severity = "critical"
    
    if len(errors) > 50:
        issues.append(f"High error rate: {len(errors)} errors found")
        severity = "high"
    
    return {
        "issue_type": "Basic Pattern Analysis (AI Unavailable)",
        "root_cause": f"Found {len(errors)} errors, {len(warnings)} warnings, and {len(exceptions)} exceptions. " + 
                     ("; ".join(issues) if issues else "No critical patterns detected."),
        "suggested_fix": "AI analysis unavailable. Please:\n1. Add DEEPSEEK_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, or GEMINI_API_KEY to .env\n2. Ensure you have API credits/billing set up\n3. Review error patterns manually",
        "severity": severity,
        "error_patterns": errors[:5],
        "affected_components": ["Unknown - requires AI analysis"],
        "timeline_analysis": "Requires AI analysis",
        "additional_recommendations": [
            "Set up AI provider for detailed analysis",
            "Review high-frequency errors",
            "Check system resources"
        ],
        "confidence_level": "low",
        "summary": f"Basic analysis found {len(errors)} errors and {len(warnings)} warnings. AI analysis unavailable - add API key for detailed insights.",
        "analyzed": False,
        "ai_provider": "fallback",
        "note": "This is a basic pattern match. For detailed analysis, configure DeepSeek (recommended), OpenAI, Anthropic, or Gemini API."
    }


def analyze_log_with_ai(
    sanitized_file_path: str, 
    original_filename: str
) -> Dict:
    """
    Analyze a sanitized log file using available AI provider
    Priority: DeepSeek → OpenAI → Anthropic → Gemini → Fallback
    Automatically tries next provider if one fails
    """
    # Read log file once
    try:
        logger.info(f"Reading sanitized log file: {sanitized_file_path}")
        log_content = read_log_file_intelligently(sanitized_file_path)
    except Exception as e:
        logger.error(f"Error reading log file: {e}")
        return {
            "issue_type": "File Read Error",
            "root_cause": f"Unable to read log file: {str(e)}",
            "suggested_fix": "Check file path and permissions",
            "severity": "unknown",
            "error": str(e),
            "analyzed": False
        }
    
    # Get all available providers
    providers = get_all_available_providers()
    
    if not providers:
        logger.warning("No AI providers available, using fallback")
        return get_fallback_analysis(log_content, original_filename)
    
    # Try each provider in order until one succeeds
    last_error = None
    
    for provider in providers:
        try:
            logger.info(f"Attempting analysis with: {provider}")
            
            if provider == "deepseek":
                result = analyze_with_deepseek(log_content, original_filename)
                logger.info(f"✓ Successfully analyzed with DeepSeek")
                return result
            
            elif provider == "openai":
                result = analyze_with_openai(log_content, original_filename)
                logger.info(f"✓ Successfully analyzed with OpenAI")
                return result
            
            elif provider == "anthropic":
                result = analyze_with_anthropic(log_content, original_filename)
                logger.info(f"✓ Successfully analyzed with Anthropic")
                return result
            
            elif provider == "gemini":
                result = analyze_with_gemini(log_content, original_filename)
                logger.info(f"✓ Successfully analyzed with Gemini")
                return result
        
        except Exception as e:
            logger.warning(f"✗ {provider} failed: {str(e)[:100]}")
            last_error = e
            continue
    
    # All providers failed, use fallback
    logger.error(f"All AI providers failed. Last error: {last_error}")
    result = get_fallback_analysis(log_content, original_filename)
    result["error"] = f"All AI providers failed. Last error: {str(last_error)}"
    result["attempted_providers"] = providers
    return result


def get_quick_stats(sanitized_file_path: str) -> Dict:
    """Get quick statistics about the log file without AI"""
    try:
        with open(sanitized_file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        error_count = sum(1 for line in lines if 'error' in line.lower())
        warning_count = sum(1 for line in lines if 'warning' in line.lower())
        exception_count = sum(1 for line in lines if 'exception' in line.lower())
        redacted_count = sum(1 for line in lines if '[REDACTED' in line)
        
        return {
            "total_lines": len(lines),
            "error_lines": error_count,
            "warning_lines": warning_count,
            "exception_lines": exception_count,
            "redacted_items": redacted_count,
            "file_size_bytes": os.path.getsize(sanitized_file_path)
        }
    except Exception as e:
        logger.error(f"Error getting file stats: {e}")
        return {}