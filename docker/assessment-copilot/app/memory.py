"""Simple file-backed RAG + structured memory for the assessment co-pilot."""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from pathlib import Path
from typing import Any


_TOKEN = re.compile(r"[a-z0-9][a-z0-9\-_.]{1,64}", re.I)


def _tokenize(text: str) -> set[str]:
    return {m.group(0).lower() for m in _TOKEN.finditer(text or "")}


class MemoryStore:
    """BM25-ish lexical retrieval over JSONL chunks + structured playbooks."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.chunks_path = self.data_dir / "chunks.jsonl"
        self.playbooks_path = self.data_dir / "playbooks.json"
        self._lock = threading.RLock()
        self._chunks: list[dict[str, Any]] = []
        self._playbooks: list[dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if self.chunks_path.exists():
            lines = self.chunks_path.read_text(encoding="utf-8").splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    self._chunks.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        if self.playbooks_path.exists():
            try:
                raw = json.loads(self.playbooks_path.read_text(encoding="utf-8"))
                if isinstance(raw, list):
                    self._playbooks = raw
            except json.JSONDecodeError:
                self._playbooks = []

    def _rewrite_chunks(self) -> None:
        """Rewrite the full JSONL so upserts do not leave stale duplicate ids on disk."""
        with self.chunks_path.open("w", encoding="utf-8") as fh:
            for chunk in self._chunks:
                fh.write(json.dumps(chunk, ensure_ascii=False) + "\n")

    def _persist_playbooks(self) -> None:
        self.playbooks_path.write_text(
            json.dumps(self._playbooks, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def upsert_chunks(self, documents: list[dict[str, Any]]) -> int:
        """Index documents. Each doc: {id?, text, scope?, project_id?, org_id?, tags?}."""
        added = 0
        with self._lock:
            for doc in documents:
                text = (doc.get("text") or "").strip()
                if not text:
                    continue
                chunk = {
                    "id": doc.get("id") or str(uuid.uuid4()),
                    "text": text,
                    "scope": doc.get("scope") or "project",
                    "project_id": doc.get("project_id"),
                    "org_id": doc.get("org_id"),
                    "tags": doc.get("tags") or [],
                    "meta": doc.get("meta") or {},
                    "indexed_at": time.time(),
                }
                # Replace same id in memory, then rewrite file (no append duplicates).
                self._chunks = [c for c in self._chunks if c.get("id") != chunk["id"]]
                self._chunks.append(chunk)
                added += 1
            if added:
                self._rewrite_chunks()
        return added

    def upsert_playbooks(self, playbooks: list[dict[str, Any]]) -> int:
        with self._lock:
            by_key = {
                (p.get("finding_class") or p.get("id") or str(i)): p
                for i, p in enumerate(self._playbooks)
            }
            for pb in playbooks:
                key = pb.get("finding_class") or pb.get("id") or str(uuid.uuid4())
                pb = {**pb, "id": key}
                by_key[key] = pb
            self._playbooks = list(by_key.values())
            self._persist_playbooks()
            return len(playbooks)

    def retrieve(
        self,
        query: str,
        *,
        limit: int = 8,
        scope: str | None = None,
        project_id: str | int | None = None,
        org_id: str | int | None = None,
    ) -> list[dict[str, Any]]:
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []

        with self._lock:
            scored: list[tuple[float, dict[str, Any]]] = []
            for chunk in self._chunks:
                if not self._scope_ok(chunk, scope, project_id, org_id):
                    continue
                c_tokens = _tokenize(chunk.get("text", ""))
                if not c_tokens:
                    continue
                overlap = len(q_tokens & c_tokens)
                if overlap == 0:
                    continue
                score = overlap / (len(q_tokens) ** 0.5)
                scored.append((score, chunk))

            scored.sort(key=lambda x: x[0], reverse=True)
            results = [c for _, c in scored[:limit]]

            # Attach matching playbooks by keyword overlap
            for pb in self._playbooks:
                blob = json.dumps(pb, ensure_ascii=False).lower()
                if any(t in blob for t in q_tokens):
                    results.append(
                        {
                            "id": f"playbook:{pb.get('id')}",
                            "text": json.dumps(pb, ensure_ascii=False),
                            "scope": "playbook",
                            "meta": {"kind": "playbook"},
                        }
                    )
                    if len(results) >= limit + 3:
                        break
            return results[: limit + 3]

    @staticmethod
    def _scope_ok(
        chunk: dict[str, Any],
        scope: str | None,
        project_id: str | int | None,
        org_id: str | int | None,
    ) -> bool:
        """Filter by configured memory scope mode."""
        chunk_scope = chunk.get("scope") or "project"
        if scope in (None, "", "project"):
            if project_id is None:
                return True
            return str(chunk.get("project_id") or "") == str(project_id)
        if scope == "org":
            if org_id is not None and chunk.get("org_id") is not None:
                return str(chunk.get("org_id")) == str(org_id)
            if project_id is not None:
                return str(chunk.get("project_id") or "") == str(project_id)
            return True
        if scope == "global":
            # Raw evidence stays project-tagged; global mode may still retrieve all
            # when running locally as configured by the operator.
            return True
        if scope == "tiered":
            # Prefer project match; allow global_eligible playbook-like chunks.
            if project_id is not None and str(chunk.get("project_id") or "") == str(project_id):
                return True
            return bool((chunk.get("meta") or {}).get("global_eligible")) or chunk_scope in (
                "global",
                "playbook",
            )
        return True

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "chunks": len(self._chunks),
                "playbooks": len(self._playbooks),
                "data_dir": str(self.data_dir),
            }
