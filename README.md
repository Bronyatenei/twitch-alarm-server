# Twitch Alarm Server

Containerized EventSub relay for the Twitch Alarm Android app. The service receives Twitch `stream.online` webhooks, deduplicates them, finds all users watching that broadcaster, and sends FCM data messages to their devices.

## Current MVP

The server exposes `/healthz`, `/eventsub/callback`, and an admin-protected `POST /v1/watchlists` endpoint. The MVP uses SQLite on a k3s PersistentVolume and one replica. It creates one EventSub subscription per unique Twitch broadcaster, so several users can share the same Twitch subscription.

The current watchlist endpoint is intentionally protected by a single `ADMIN_API_KEY`. It is suitable for initial testing, not yet for public registration. A later step should add proper user authentication and per-user API credentials.

## Required GitHub Secrets

Create these repository secrets before pushing to `main`:

- `SERVER_HOST` — server IP or DNS name.
- `SERVER_USER` — SSH user with passwordless `sudo k3s kubectl` access.
- `SERVER_SSH_KEY` — private key for that user.
- `GHCR_USERNAME` — GitHub username used to pull the private image from GHCR.
- `GHCR_PULL_TOKEN` — GitHub token with read-only package access (`read:packages`).
- `TWITCH_CLIENT_ID` and `TWITCH_CLIENT_SECRET` — Twitch Developer Application credentials.
- `EVENTSUB_CALLBACK` — public HTTPS URL ending in `/eventsub/callback`, for example `https://eventsub.example.com/eventsub/callback`.
- `EVENTSUB_SECRET` — random ASCII secret, 10–100 characters.
- `FIREBASE_SERVICE_ACCOUNT_JSON` — the complete Firebase Admin service-account JSON, kept only in GitHub Secrets.
- `ADMIN_API_KEY` — long random value used by the protected watchlist endpoint.

Do not commit any of these values or a Firebase JSON file.

## Server prerequisites

The server must already have k3s, an SSH account, and a public DNS name pointing to the server. The k3s Traefik ingress must be reachable on ports 80 and 443. The included Ingress expects cert-manager with a `letsencrypt-prod` ClusterIssuer; alternatively replace the TLS section with a certificate managed by your existing ingress setup.

The current Ingress is configured for `bronyatenei.site`. Set the same URL in `EVENTSUB_CALLBACK`.

The GitHub Actions workflow builds the image, pushes it to GHCR, copies the manifests to the server, creates/updates the Kubernetes Secret, and waits for the rollout.

## Local development

```bash
cp .env.example .env
npm install
npm start
```

The EventSub endpoint must still be public HTTPS for Twitch verification. Use a tunnel only for development.
