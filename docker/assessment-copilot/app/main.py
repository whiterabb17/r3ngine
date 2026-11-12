"""Assessment Copilot HTTP API — local LLM + memory (separate from AI Hub)."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from app.memory import MemoryStore
from app.prompts import FORBIDDEN_SUBSTRINGS, SYSTEM_PROMPT

DATA_DIR = Path(os.environ.get("COPILOT_DATA_DIR", "/data"))
OLLAMA_URL = os.environ.get("ASSESSMENT_OLLAMA_URL", "http://assessment-ollama:11434").rstrip("/")
DEFAULT_MODEL = os.environ.get("COPILOT_MODEL_DEFAULT", "qwen2.5:7b-instruct")

app = FastAPI(title="r3ngine Assessment Copilot", version="0.1.0")
store = MemoryStore(DATA_DIR)


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(default_factory=list)
    model: str | None = None
    scope: str | None = "project"
    project_id: str | int | None = None
    org_id: str | int | None = None
    temperature: float = 0.2
    max_tokens: int = 2048


class IndexRequest(BaseModel):
    documents: list[dict[str, Any]] = Field(default_factory=list)
    playbooks: list[dict[str, Any]] = Field(default_factory=list)


class RetrieveRequest(BaseModel):
    query: str
    limit: int = 8
    scope: str | None = "project"
    project_id: str | int | None = None
    org_id: str | int | None = None


def _sanitize_assistant(text: str) -> str:
    lowered = text.lower()
    for bad in FORBIDDEN_SUBSTRINGS:
        if bad in lowered:
            return (
                text
                + "\n\n[copilot-note] Response referenced disallowed offensive tooling "
                "keywords. Prefer SAFE PoC catalog templates and stack follow-up tools."
            )
    return text


async def _ollama_chat(
    *,
    model: str,
    messages: list[dict[str, str]],
    temperature: float,
    max_tokens: int,
) -> str:
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
        },
    }
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(f"{OLLAMA_URL}/api/chat", json=payload)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"assessment-ollama unreachable: {exc}") from exc
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=f"ollama error: {resp.text[:500]}")
    data = resp.json()
    content = ((data.get("message") or {}).get("content")) or data.get("response") or ""
    return str(content)


@app.get("/health")
async def health() -> dict[str, Any]:
    ollama_ok = False
    ollama_version = None
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{OLLAMA_URL}/api/version")
            if r.status_code < 400:
                ollama_ok = True
                ollama_version = (r.json() or {}).get("version")
    except httpx.HTTPError:
        ollama_ok = False
    return {
        "status": "ok" if ollama_ok else "degraded",
        "ollama": {"url": OLLAMA_URL, "reachable": ollama_ok, "version": ollama_version},
        "model_default": DEFAULT_MODEL,
        "memory": store.stats(),
    }


@app.get("/models")
async def list_models() -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{OLLAMA_URL}/api/tags")
            r.raise_for_status()
            return r.json()
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail=f"assessment-ollama unreachable: {exc}") from exc


@app.post("/index")
async def index_docs(body: IndexRequest) -> dict[str, Any]:
    n_docs = store.upsert_chunks(body.documents)
    n_pb = store.upsert_playbooks(body.playbooks) if body.playbooks else 0
    return {"indexed_documents": n_docs, "indexed_playbooks": n_pb, "memory": store.stats()}


@app.post("/retrieve")
async def retrieve(body: RetrieveRequest) -> dict[str, Any]:
    hits = store.retrieve(
        body.query,
        limit=body.limit,
        scope=body.scope,
        project_id=body.project_id,
        org_id=body.org_id,
    )
    return {"hits": hits}


@app.post("/chat")
async def chat(body: ChatRequest) -> dict[str, Any]:
    model = body.model or DEFAULT_MODEL
    user_blob = " ".join(m.content for m in body.messages if m.role == "user")[-2000:]
    hits = store.retrieve(
        user_blob or "assessment findings",
        limit=6,
        scope=body.scope,
        project_id=body.project_id,
        org_id=body.org_id,
    )
    context_blocks = []
    for h in hits:
        context_blocks.append(f"- ({h.get('scope')}) {h.get('text', '')[:1200]}")
    memory_block = "\n".join(context_blocks) if context_blocks else "(no indexed memory yet)"

    system = (
        SYSTEM_PROMPT
        + "\n\n## Retrieved assessment memory\n"
        + memory_block
    )
    messages = [{"role": "system", "content": system}]
    for m in body.messages:
        if m.role in ("user", "assistant", "system"):
            messages.append({"role": m.role, "content": m.content})

    content = await _ollama_chat(
        model=model,
        messages=messages,
        temperature=body.temperature,
        max_tokens=body.max_tokens,
    )
    content = _sanitize_assistant(content)
    return {
        "model": model,
        "message": {"role": "assistant", "content": content},
        "memory_hits": len(hits),
    }
