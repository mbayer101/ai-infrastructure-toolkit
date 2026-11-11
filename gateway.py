import os
import re
import time
import json
import uuid
import hashlib
import logging
from typing import List, Optional, Dict, Any, AsyncGenerator
import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Security, Request, Response, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
import litellm
from litellm import acompletion
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# ---------------------------------------------------------
# 1. SIEM Structured Telemetry Logging
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

litellm.suppress_debug_info = True

app = FastAPI(
    title="Enterprise AI Gateway - High Assurance Edition",
    description="Multi-cloud AI gateway with Redis sliding limits, semantic caching, spend caps, and Prometheus telemetry.",
    version="3.0.0"
)

# ---------------------------------------------------------
# 2. Prometheus Observability Metrics
# ---------------------------------------------------------
REQUEST_COUNTER = Counter("ai_gateway_requests_total", "Total requests", ["tenant", "model", "status"])
LATENCY_HISTOGRAM = Histogram("ai_gateway_latency_seconds", "Inference latency", ["model"])
TOKEN_COUNTER = Counter("ai_gateway_tokens_total", "Tokens utilized", ["tenant", "type"])
CACHE_HITS = Counter("ai_gateway_cache_hits_total", "Semantic cache hits", ["model"])

# ---------------------------------------------------------
# 3. Redis Connection Pool
# ---------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
redis_client = aioredis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True, max_connections=25)

# Virtual Keys Registry with RPM, Spend Limits ($), and Token Caps
VIRTUAL_KEYS: Dict[str, Dict[str, Any]] = {
    "sk-corp-master-admin": {"tenant": "secops-admin", "rpm": 120, "max_tokens": 8192, "spend_cap_usd": 1000.0},
    "sk-dev-team-alpha": {"tenant": "developer-sandbox", "rpm": 30, "max_tokens": 4096, "spend_cap_usd": 50.0},
}

# Approximate cost estimation per 1k tokens (blended input/output)
ESTIMATED_COST_PER_1K = {
    "gpt-4o": 0.0075,
    "claude-3-5-sonnet": 0.0060,
    "default": 0.0050
}

# ---------------------------------------------------------
# 4. Redis Rate Limiter & Spend Quota Enforcer
# ---------------------------------------------------------
security = HTTPBearer()

async def enforce_security_and_limits(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, Any]:
    token = credentials.credentials
    key_meta = VIRTUAL_KEYS.get(token)

    if not key_meta and token != os.getenv("GATEWAY_MASTER_KEY", "sk-corp-master-admin"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Invalid virtual API key.",
        )

    key_meta = key_meta or {"tenant": "system-master", "rpm": 1000, "max_tokens": 16384, "spend_cap_usd": 10000.0}

    tenant = key_meta["tenant"]
    now = time.time()
    rate_key = f"ratelimit:{token}"
    spend_key = f"spend:{tenant}:{time.strftime('%Y-%m')}"

    # Check monthly spend cap
    current_spend = float(await redis_client.get(spend_key) or 0.0)
    if current_spend >= key_meta["spend_cap_usd"]:
        logger.warning(f"Tenant {tenant} exceeded monthly spend budget (${current_spend:.2f} >= ${key_meta['spend_cap_usd']})")
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail=f"Budget Cap Exceeded: Tenant has reached its monthly limit of ${key_meta['spend_cap_usd']}."
        )

    # Atomic sliding-window rate check
    try:
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(rate_key, 0, now - 60.0)
        pipe.zcard(rate_key)
        pipe.zadd(rate_key, {str(now): now})
        pipe.expire(rate_key, 65)
        _, current_request_count, _, _ = await pipe.execute()

        if current_request_count >= key_meta["rpm"]:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded: Capacity is {key_meta['rpm']} requests/minute."
            )
    except HTTPException:
        raise
    except Exception as redis_err:
        logger.error(f"Redis rate check error: {str(redis_err)}")

    return key_meta

# ---------------------------------------------------------
# 5. Guardrails: Dual Inbound/Outbound PII & Prompt Defense
# ---------------------------------------------------------
PII_PATTERNS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
    "API_KEY": re.compile(r"(sk-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16})"),
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

def sanitize_input(text: str, mask_pii: bool = True) -> str:
    for rule in COMPILED_INJECTION_RULES:
        if rule.search(text):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Security Guardrail: Prompt rejected due to jailbreak/injection signature."
            )
    if mask_pii:
        for entity_type, pattern in PII_PATTERNS.items():
            text = pattern.sub(f"[REDACTED_{entity_type}]", text)
    return text

def sanitize_output(text: str) -> str:
    """Outbound scan to prevent model hallucination of credentials or leaked PII."""
    for entity_type, pattern in PII_PATTERNS.items():
        text = pattern.sub(f"[REDACTED_{entity_type}]", text)
    return text

# ---------------------------------------------------------
# 6. Multi-Provider Fallback Routing Map
# ---------------------------------------------------------
FALLBACK_ROUTING_MAP = {
    "claude-3-5-sonnet": [
        "bedrock/anthropic.claude-3-5-sonnet-20241022-v1:0",
        "anthropic/claude-3-5-sonnet-20241022",
        "openai/gpt-4o"
    ],
    "gpt-4o": [
        "openai/gpt-4o",
        "bedrock/anthropic.claude-3-5-sonnet-20241022-v1:0"
    ]
}

# ---------------------------------------------------------
# 7. Request Schemas
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
    use_cache: Optional[bool] = True

# ---------------------------------------------------------
# 8. API Endpoints
# ---------------------------------------------------------
@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": time.time(), "cache": "enabled"}

@app.get("/metrics")
def get_metrics():
    """Prometheus scraping endpoint."""
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.post("/v1/chat/completions")
async def chat_completions(
    request: ChatCompletionRequest,
    raw_request: Request,
    auth_meta: Dict[str, Any] = Depends(enforce_security_and_limits)
):
    request_id = str(uuid.uuid4())
    start_time = time.time()
    tenant = auth_meta["tenant"]
    client_ip = raw_request.client.host if raw_request.client else "unknown"

    # Step 1: Inbound Sanitization
    sanitized_messages = []
    for msg in request.messages:
        clean_content = sanitize_input(msg.content, mask_pii=request.mask_pii)
        sanitized_messages.append({"role": msg.role, "content": clean_content})

    # Step 2: Semantic Cache Lookup (Exact Canonical Prompt Hash)
    if request.use_cache and not request.stream:
        cache_signature = hashlib.sha256(
            json.dumps({"m": request.model, "msg": sanitized_messages, "t": request.temperature}, sort_keys=True).encode()
        ).hexdigest()
        cache_key = f"cache:completion:{cache_signature}"

        cached_response = await redis_client.get(cache_key)
        if cached_response:
            CACHE_HITS.labels(model=request.model).inc()
            REQUEST_COUNTER.labels(tenant=tenant, model=request.model, status="cache_hit").inc()
            logger.info(f"Cache Hit for {request.model} (Request {request_id})")
            return JSONResponse(content=json.loads(cached_response))

    # Step 3: Handle SSE Streaming
    model_candidates = FALLBACK_ROUTING_MAP.get(request.model, [request.model])

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

    # Step 4: Non-Streaming Execution with Fallover
    last_exception = None
    for target_model in model_candidates:
        try:
            with LATENCY_HISTOGRAM.labels(model=target_model).time():
                response = await acompletion(
                    model=target_model,
                    messages=sanitized_messages,
                    temperature=request.temperature,
                    max_tokens=request.max_tokens or auth_meta.get("max_tokens"),
                    timeout=30.0
                )

            latency = round(time.time() - start_time, 3)
            prompt_tokens = response.usage.prompt_tokens if hasattr(response, "usage") and response.usage else 0
            completion_tokens = response.usage.completion_tokens if hasattr(response, "usage") and response.usage else 0
            total_tokens = prompt_tokens + completion_tokens

            # Step 5: Cost Accounting Update in Redis
            cost_rate = ESTIMATED_COST_PER_1K.get(request.model, ESTIMATED_COST_PER_1K["default"])
            estimated_cost = (total_tokens / 1000.0) * cost_rate
            spend_key = f"spend:{tenant}:{time.strftime('%Y-%m')}"
            await redis_client.incrbyfloat(spend_key, estimated_cost)

            # Record Prometheus Metrics
            TOKEN_COUNTER.labels(tenant=tenant, type="prompt").inc(prompt_tokens)
            TOKEN_COUNTER.labels(tenant=tenant, type="completion").inc(completion_tokens)
            REQUEST_COUNTER.labels(tenant=tenant, model=target_model, status="success").inc()

            # Step 6: Outbound Guardrails (Clean Output)
            if response.choices and hasattr(response.choices[0].message, "content"):
                raw_reply = response.choices[0].message.content
                response.choices[0].message.content = sanitize_output(raw_reply)

            # Step 7: Populate Redis Cache (TTL: 1 Hour)
            if request.use_cache:
                response_dict = response.model_dump() if hasattr(response, "model_dump") else json.loads(json.dumps(response))
                await redis_client.setex(cache_key, 3600, json.dumps(response_dict))

            # SIEM Audit Logging
            logger.info(
                f"Gateway Transaction: {target_model}",
                extra={"telemetry": {
                    "request_id": request_id,
                    "tenant": tenant,
                    "model": target_model,
                    "latency_sec": latency,
                    "tokens": total_tokens,
                    "estimated_cost_usd": round(estimated_cost, 6),
                    "status": "SUCCESS"
                }}
            )
            return response

        except Exception as e:
            logger.warning(f"Target '{target_model}' failed: {str(e)}. Attempting next candidate...")
            last_exception = e
            continue

    REQUEST_COUNTER.labels(tenant=tenant, model=request.model, status="failure").inc()
    raise HTTPException(
        status_code=status.HTTP_502_BAD_GATEWAY,
        detail=f"All upstream AI model providers failed. Cause: {str(last_exception)}"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway:app", host="0.0.0.0", port=4000, reload=True)

