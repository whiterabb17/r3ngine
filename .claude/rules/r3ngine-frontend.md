---
description: Frontend conventions for r3ngine — React 18, TypeScript, Vite, and REST API client usage.
---

# r3ngine – Frontend conventions

## Scope

Apply these guidelines when working on frontend code:

- TypeScript/JavaScript files under `frontend/src/`
- React components, hooks, stores (Zustand)
- API client layer (`frontend/src/api/`)

## React & TypeScript style

- Always use `const` or `let`; never `var`.
- Prefer function components with hooks over class components.
- Type all component props with TypeScript interfaces or types; no `any` without justification.
- Keep components small and focused — if a component exceeds ~150 lines, extract sub-components.

## API calls

- Do not hardcode backend URLs inside components. All API calls must go through the client layer in `frontend/src/api/`.
- Use the established API functions; add new ones to the appropriate module rather than inlining `fetch`/`axios` calls.

### Example — avoid inline fetch

```typescript
// ❌ Bad
const res = await fetch('/api/v1/subdomains/?scan_id=42');

// ✅ Good — use the API layer
import { getSubdomains } from '../api/subdomain';
const subdomains = await getSubdomains(scanId);
```

## State management

- Global state lives in Zustand stores under `frontend/src/store/`.
- Do not duplicate server state in Zustand; use it for UI state and local filters.
- For server-state (data that comes from the API), prefer local `useState` + `useEffect` or a query hook.

## Responsive design

- All UI changes must respect responsive design for display across screen sizes.

## Build verification

The frontend is **not** built inside the running container. `docker/web/Dockerfile` compiles it
in a separate `frontend-builder` stage and copies only `dist` into the final image, and
`docker/docker-compose.yml` masks `/usr/src/app/frontend/node_modules` with an anonymous volume —
so `npm run build` in `r3ngine-web-1` fails with `tsc: not found`.

- Verify locally in `frontend/` before marking a task complete:
  ```bash
  npx tsc -b
  ```
  ```bash
  npm run lint
  ```
- `npm run build` locally is the fuller check (type-check + Vite bundle) when the change touches
  imports, assets or the bundle itself.

## Deploying a frontend change

Rebuild the web image — Django serves the bundle from the image's `/usr/src/frontend/dist`
(`web/reNgine/settings.py`), and the container entrypoint runs `collectstatic --clear` on start:

```bash
make build-web
```
```bash
make up
```

`make up` recreates `web`, `temporal-python-orchestrator` and `temporal-go-executor`, which share
that image. There is a mounted-source escape hatch — `settings.py` prefers
`/usr/src/app/frontend/dist` when it exists — but building into the mounted repo leaves
root-owned `node_modules/` and `dist/` that then shadow every later image build. Use it only for
a one-off check, and delete both afterwards.

## Security cross-reference

- For XSS and injection rules (dangerouslySetInnerHTML, href URL validation), see `r3ngine-security.md`.
