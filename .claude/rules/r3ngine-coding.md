---
description: Core coding standards for r3ngine (Python/Django, TypeScript/React, PostgreSQL/Neo4j) and high-level project guidelines.
---

# r3ngine – Core coding standards

You are an expert in Python/Django/TypeScript/React/PostgreSQL/Neo4j development and consistently deliver high-quality, non-duplicated code that follows KISS, DRY and SOLID principles.

## Project mantras

- Do what is right
- Security by design
- Security by default
- Doing the right thing should be easy
- Batteries included – it just works
- No-nonsense bingo – no time to waste
- Better explicit than magical

## General expectations

- Follow existing patterns in the codebase before introducing new ones.
- Add type hints to all new Python code; TypeScript types to all new frontend code.
- Every code change must include appropriate tests.
- All code and comments must be written in English.
- Avoid comments that narrate refactors; only explain non-obvious intent.

## Architecture

Keep the project modular and layered to avoid circular dependencies:

- Leaf modules (like `common_func/`, `definitions.py`, or utility helpers) sit at the bottom.
- Core business logic (task functions, activity implementations, graph utilities) sits in the middle.
- Orchestration layers (Temporal workflows, HTTP views, Django Channels consumers) sit at the top.

## Tooling

- Follow PEP8; lint with `flake8`, format with `black`:
  - Run inside the container: `docker exec -it r3ngine-web-1 bash -c "cd /usr/src/app && flake8 ."`
  - Format: `docker exec -it r3ngine-web-1 bash -c "cd /usr/src/app && black ."`
  - `web/` is mounted into the container, so Python edits take effect without a rebuild —
    only restart the affected service (`make restart-apps`). Frontend changes DO need an
    image rebuild; see `r3ngine-frontend.md`.
- Common compose operations have Makefile targets, which pass the right `--env-file` and
  `-f docker/docker-compose.yml`: `make up`, `make build-web`, `make restart-apps`,
  `make migrate`, `make logs`. A bare `docker compose …` from the repo root finds no
  compose file.

## API usage

- REST API is JWT-authenticated. For automated tests, use the Django test client (`self.client`) with a forced login — do not rely on CSRF tokens.
- WebSocket endpoints live at `ws://localhost:8000/ws/scan/{scan_id}/` and are backed by Django Channels + Redis.

## Cross-reference rules

- For Python/Django backend architecture, see `r3ngine-python-backend.md`.
- For React/Vite frontend conventions, see `r3ngine-frontend.md`.
- For testing conventions, see `r3ngine-tests.md`.
- For Temporal workflow and activity patterns, see `r3ngine-temporal.md` and the skill `r3ngine-context`.

## Change management

- Do not perform radical changes without explicit discussion.
- Do not add new Python dependencies without approval; add them to `web/requirements.txt`.
- Do not add new npm dependencies without approval; add them to `frontend/package.json`.
- Do not modify `docker/docker-compose.yml` or `docker/web/Dockerfile` without understanding the full build pipeline (the Dockerfile builds the frontend in its own stage — see `r3ngine-frontend.md`).
- Any change that touches a module in `temporal/workflows/` (or the shim `temporal_workflows.py`) must be reviewed for determinism violations (see `r3ngine-temporal.md`).