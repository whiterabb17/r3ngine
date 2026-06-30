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

- After any frontend change, run `npm run build` inside the container to confirm no TypeScript errors and no broken imports before marking the task complete:
  ```bash
  docker exec -it r3ngine-web-1 bash -c "cd /usr/src/app/frontend && npm run build"
  ```

## Security cross-reference

- For XSS and injection rules (dangerouslySetInnerHTML, href URL validation), see `r3ngine-security.md`.
