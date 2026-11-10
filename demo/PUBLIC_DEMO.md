# Public demo link: let others use the system from their own devices

`demo\start-public-demo.ps1` opens a temporary **https://** link to the system running on this laptop, so the
panel (or anyone) can sign in from their own phone or laptop. Face ID works over it because the link is HTTPS
(browsers only allow the camera on HTTPS pages, or on `127.0.0.1` on the same computer).

Use it as a backup. Presenting from this laptop at http://127.0.0.1:5173 needs none of this.

## Before the day (once)

1. The system works normally on this laptop (`docker compose up -d`, sign in at http://127.0.0.1:5173).
2. The demo accounts exist (see `docs/LIVE_DETECTION_DEMO.md` and `demo/README.md`). Their emailed codes go to
   **your** inbox, so have it open on your phone during the demonstration.
3. Run the script once at home to check it works (below). The first run downloads `cloudflared` (Cloudflare's
   official tunnel program, about 60 MB) into `demo\tools\`, which git ignores.

## Start

From the repository root, in PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1
```

It takes one to three minutes and shows five steps: Docker check, system start (no rebuild), tunnel, backend
restart with the public address for email links, and a check that the link answers from the internet. It
ends with the link in a green box, already copied to the clipboard, for example
`https://example-words-here.trycloudflare.com`.

Share the link (read it out, or paste it in a chat). On their device they:

1. open the link in any browser (nothing to install);
2. sign in with a demo account and password;
3. enter the emailed code, which arrives in **your** inbox: read it out to them. Face ID is offered only for an
   account whose face is enrolled.

Everything they do appears live on your dashboard: sessions, live alerts (R1-R5) and the audit log.

To also share the attendance demo module, start it first and add `-WithAttendance`:

```powershell
powershell -ExecutionPolicy Bypass -File demo\start-demo.ps1
powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1 -WithAttendance
```

## Stop

```powershell
powershell -ExecutionPolicy Bypass -File demo\start-public-demo.ps1 -Stop
```

This closes the link (it stops working immediately) and restarts the backend with its normal settings (about a
minute). Always stop it when the demonstration is over.

## Good to know

- **The link changes every time** you start it. It works only while this laptop is on, awake and online.
- **Nothing in your settings is edited.** The public address is applied on top of the normal configuration by
  `demo\public-demo.compose.yml` while the link is open; `-Stop` (or a plain `docker compose up -d`) removes it.
- **It is public while open.** Anyone with the link reaches the sign-in page; they still need an account,
  the password and the second factor, and the usual rate limits apply. Only the website goes through the
  link: the database and port 8000 are not exposed.
- Sessions record each visitor's real address (the script sets `TRUSTED_PROXY_HOPS=2` while the link is open),
  so detection features such as "new IP" behave as they would for real users.
- Running the script again while a link is open just shows the open link.

## If something goes wrong

| What you see | What to do |
|---|---|
| "Docker is not running" | Start Docker Desktop, wait until it shows "running", run the script again |
| "docker compose failed" on a fresh copy | Build once: `docker compose up -d --build` (downloads about 1 GB; do it at home) |
| "The tunnel did not start" or the link never answers | The network may block tunnels. Switch the laptop to a phone hotspot and run the script again (stop first). If it still fails, present from this laptop instead |
| "Download failed" for cloudflared | Check the connection, or install it: `winget install --id Cloudflare.cloudflared` |
| No code arrives | Check spam; codes expire after 5 minutes, and "Resend" sends a new one |
| The link works but email links in setup/reset emails point to 127.0.0.1 | The script was not used to start the link; run `-Stop`, then start again with the script |
