import os
import re
import time
import json
import uuid
import logging
from typing import List, Optional, Dict, Any, AsyncGenerator
from fastapi import FastAPI, HTTPException, Security, Request, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
import litellm
from litellm import completion, acompletion

# ---------------------------------------------------------
# 1. Structured JSON Logging for SIEM (Elastic / Datadog)
# ---------------------------------------------------------
class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if hasattr(record, "telemetry"):
            log_obj["telemetry"] = record.telemetry
        return json.dumps(log_obj)

logger = logging.getLogger("AIGateway")
logger.setLevel(logging.INFO)
log_handler = logging.StreamHandler()
log_handler.setFormatter(JSONFormatter())
logger.addHandler(log_handler)

# Suppress noisy LiteLLM debug output in production
litellm.suppress_debug_info = True

app = FastAPI(
    title="Enterprise Resilient AI Gateway",
    description="High-availability, OpenAI-compliant gateway with PII filtering, prompt defense, and automated multi-cloud failover.",
    version="2.0.0"
)

# ---------------------------------------------------------
# 2. Virtual Keys, Quotas & Rate Limiting (In-Memory)
# ---------------------------------------------------------
security = HTTPBearer()

# Virtual key registry with rpm (requests per minute) and model allowances
VIRTUAL_KEYS: Dict[str, Dict[str, Any]] = {
    "sk-corp-master-admin": {"tenant": "secops-admin", "rpm": 120, "max_tokens": 8192},
    "sk-dev-team-alpha": {"tenant": "developer-sandbox", "rpm": 30, "max_tokens": 4096},
}

# Simple sliding-window rate tracking
RATE_LIMIT_STORE: Dict[str, List[float]] = {}

def enforce_security_and_limits(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    token = credentials.credentials
    key_meta = VIRTUAL_KEYS.get(token)

    if not key_meta and token != os.getenv("GATEWAY_MASTER_KEY", "sk-default-master"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid virtual API key.",
        )
    
    # Default policy for master key
    key_meta = key_meta or {"tenant": "system-master", "rpm": 1000, "max_tokens": 16384}
    
    # Rate limit check (rolling 60-second window)
    now = time.time()
    timestamps = RATE_LIMIT_STORE.get(token, [])
    timestamps = [t for t in timestamps if now - t < 60]
    
    if len(timestamps) >= key_meta["rpm"]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: Cap is {key_meta['rpm']} requests/min.",
        )
    
    timestamps.append(now)
    RATE_LIMIT_STORE[token] = timestamps
    return key_meta

# ---------------------------------------------------------
# 3. Security Guardrails: PII Redaction & Prompt Defense
# ---------------------------------------------------------
PII_PATTERNS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "US_PHONE": re.compile(r"\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b"),
}

PROMPT_INJECTION_SIGNATURES = [
    r"ignore (all )?previous instructions",
    r"disregard (all )?(prior|system) instructions",
    r"system override",
    r"you are now in developer mode",
    r"DAN mode enabled",
    r"reveal (your )?(system prompt|instructions)",
]
COMPILED_INJECTION_RULES = [re.compile(p, re.IGNORECASE) for p in PROMPT_INJECTION_SIGNATURES]

def inspect_and_sanitize(text: str, mask_pii: bool = True) -> str:
    """Inspects text for prompt injection signatures and masks critical PII."""
    # 1. Threat Detection: Prompt Injection
    for rule in COMPILED_INJECTION_RULES:
        if rule.search(text):
            logger.warning(
                "Prompt injection pattern detected",
                extra={"telemetry": {"event": "security_violation", "pattern": rule.pattern}}
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security Guardrail Violation: Input rejected due to detected jailbreak/prompt injection pattern."
            )

    # 2. Privacy Control: In-Flight PII Masking
    if mask_pii:
        for entity_type, pattern in PII_PATTERNS.items():
            text = pattern.sub(f"[REDACTED_{entity_type}]", text)
            
    return text

# ---------------------------------------------------------
# 4. Multi-Provider Fallback Routing Table
# ---------------------------------------------------------
# If the primary model fails or encounters rate limits, failover down the chain
FALLBACK_ROUTING_MAP = {
    "claude-3-5-sonnet": [
        "bedrock/anthropic.claude-3-5-sonnet-20241022-v1:0", # Primary: Bedrock VPC Endpoint
        "anthropic/claude-3-5-sonnet-20241022",              # Fallback 1: Direct Anthropic
        "openai/gpt-4o"                                      # Fallback 2: Cross-provider parity
    ],
    "gpt-4o": [
        "openai/gpt-4o",
        "bedrock/anthropic.claude-3-5-sonnet-20241022-v1:0"
    ]
}

# ---------------------------------------------------------
# 5. Request & Response Schemas
# ---------------------------------------------------------
class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    temperature: Optional[float] = 0.7
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False
    mask_pii: Optional[bool] = True

# ---------------------------------------------------------
# 6. Gateway Endpoints
# ---------------------------------------------------------
@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "active_providers": ["bedrock", "anthropic", "openai"],
        "timestamp": time.time()
    }

@app.post("/v1/chat/completions")
async def chat_completions(
    request: ChatCompletionRequest,
    raw_request: Request,
    auth_meta: Dict[str, Any] = Depends(enforce_security_and_limits)
):
    request_id = str(uuid.uuid4())
    start_time = time.time()
    client_ip = raw_request.client.host if raw_request.client else "unknown"

    # Step 1: Sanitize and redact all user messages
    sanitized_messages = []
    for msg in request.messages:
        clean_content = inspect_and_sanitize(msg.content, mask_pii=request.mask_pii)
        sanitized_messages.append({"role": msg.role, "content": clean_content})

    # Step 2: Determine model candidates (Primary + Fallbacks)
    model_candidates = FALLBACK_ROUTING_MAP.get(request.model, [request.model])

    # Step 3: Handle SSE Streaming Requests
    if request.stream:
        async def stream_generator() -> AsyncGenerator[str, None]:
            response = await acompletion(
                model=model_candidates[0],
                messages=sanitized_messages,
                temperature=request.temperature,
                max_tokens=request.max_tokens,
                stream=True
            )
            async for chunk in response:
                chunk_json = chunk.model_dump_json() if hasattr(chunk, "model_dump_json") else json.dumps(chunk)
                yield f"data: {chunk_json}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    # Step 4: Non-Streaming with Automated Failover Execution
    last_exception = None
    for target_model in model_candidates:
        try:
            logger.info(f"Routing request {request_id} to upstream target: {target_model}")
            
            response = await acompletion(
                model=target_model,
                messages=sanitized_messages,
                temperature=request.temperature,
                max_tokens=request.max_tokens or auth_meta.get("max_tokens"),
                timeout=30.0
            )

            latency = round(time.time() - start_time, 3)
            usage = response.usage.model_dump() if hasattr(response, "usage") and response.usage else {}

            # Emit SIEM Audit Record
            logger.info(
                f"Gateway Transaction Completed: {target_model}",
                extra={"telemetry": {
                    "request_id": request_id,
                    "tenant": auth_meta["tenant"],
                    "client_ip": client_ip,
                    "requested_model": request.model,
                    "served_model": target_model,
                    "latency_sec": latency,
                    "prompt_tokens": usage.get("prompt_tokens", 0),
                    "completion_tokens": usage.get("completion_tokens", 0),
                    "status": "SUCCESS"
                }}
            )
            return response

        except Exception as e:
            logger.warning(f"Execution failed on target '{target_model}': {str(e)}. Attempting fallback...")
            last_exception = e
            continue

    # Step 5: Fail-closed fallback if all providers fail
    total_duration = round(time.time() - start_time, 3)
    logger.error(
        f"All model candidates failed for request {request_id}",
        extra={"telemetry": {
            "request_id": request_id,
            "tenant": auth_meta["tenant"],
            "requested_model": request.model,
            "latency_sec": total_duration,
            "status": "FAILED",
            "error": str(last_exception)
        }}
    )
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"All upstream AI model providers failed. Root cause: {str(last_exception)}"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway:app", host="0.0.0.0", port=4000, reload=True)

