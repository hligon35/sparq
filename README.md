# SparQ Workspace

This workspace serves the public site and the internal portal. The portal can link to the SparQ Plug app.

## Structure
- `index.html`, `about.html`, `services.html`, `contact.html`: Public site. The nav Login goes to `portal/public/login.html`.
- `portal/`: Node/Express portal app.
  - `public/`: Static dashboard/login pages.
  - `public/sparkplug/`: Placeholder page so the link doesnt 404 during dev.
- `sparq-plug-main/`: Next.js app for SparQ Plug.

## Run locally
1) Portal
- In PowerShell:
  - `cd portal`
  - `npm install`
  - `npm run dev`
- Open http://localhost:3003

2) SparQ Plug (Next.js)
- In a separate terminal:
  - `cd sparq-plug-main`
  - `npm install`
  - `npm run dev`
- App runs at http://localhost:3000 (or your chosen port).

3) Optional proxy from portal 
- To open SparQ Plug inside the portal path `/sparkplug`, set the env var and restart the portal:
  - PowerShell (example for port 3000):
    - `$env:SPARQ_PLUG_URL = 'http://localhost:3000'`
    - `npm run dev`
- Now `http://localhost:3003/sparkplug` will forward to the Next.js dev server.

Notes
- When deploying, proxy `/sparkplug/` in your reverse proxy (Nginx) to the running Next.js service.
- The placeholder at `portal/public/sparkplug/index.html` can be removed once the proxy/app is active.
