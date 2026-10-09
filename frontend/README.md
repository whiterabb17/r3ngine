# r3ngine frontend

React + TypeScript + Vite. See the repository `README.md` and `documents/` for the
architecture; this file only covers frontend-specific chores.

## Regenerating the API types

`src/types/api.ts` is generated from the backend's drf-yasg schema — never edit it by hand.

1. Export the Swagger 2.0 schema to `web/openapi.json` (from `web/`, with the Postgres the
   test settings use reachable on `127.0.0.1:5432`):

   ```bash
   DJANGO_SETTINGS_MODULE=reNgine.settings_test_local \
     python manage.py generate_swagger -o -f json openapi.json
   ```

   Inside the stack: `docker exec r3ngine-web-1 bash -c "cd /usr/src/app && python3 manage.py generate_swagger -o -f json openapi.json"`.

2. Convert it and generate the types (from `frontend/`):

   ```bash
   npm run generate-types
   ```

   The script runs `swagger2openapi` (writes the ignored `web/openapi3.json`) and
   `openapi-typescript` through `npx`, so the first run downloads both packages.

3. Run `npx tsc -b` and fix what the new types surface.

drf-yasg cannot infer the return type of a `SerializerMethodField` (it is emitted as
`string`) or the shape of a `JSONField` (an empty object). Feature type modules restate
those fields on top of the generated schema — e.g. `Domain`, `ScanHistory` and
`Vulnerability` — so check them when a serializer's method fields change.
