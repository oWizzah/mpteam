# MP TEAM — GitHub Pages + Discord Admin + Cloudflare D1

This package contains:
- `site/index.html`: public bilingual GitHub Pages site and live bookmarklet.
- `worker/src.js`: Cloudflare Worker API, Discord OAuth login, session authorization, player CRUD.
- `worker/admin.html`: private admin interface served by Worker.
- `worker/schema.sql`: D1 tables and initial roster (19 entries from the provided list).

## Setup (no card required where Cloudflare free tier is available)

1. Create a Cloudflare account and install Node.js 20+.
2. In `worker`, run `npm install` and `npx wrangler login`.
3. Create the D1 database: `npx wrangler d1 create mp-team-db`.
4. Copy the `database_id` returned by Cloudflare into `worker/wrangler.toml`.
5. Run `npm run db:init` to create tables and seed players.
6. In the [Discord Developer Portal](https://discord.com/developers/applications), create/select an application. In **OAuth2**, add the redirect URL `https://YOUR-WORKER.workers.dev/auth/callback`. You will know your Worker hostname after the first deployment; update it in the portal before logging in.
7. Configure Worker secrets and variables. From `worker`, run:
   - `npx wrangler secret put DISCORD_CLIENT_SECRET`
   - `npx wrangler secret put DISCORD_CLIENT_ID`
   - `npx wrangler secret put ADMIN_DISCORD_ID`
   - `npx wrangler secret put PUBLIC_SITE_ORIGIN` (e.g. `https://YOURNAME.github.io` — **origin only**, no path)
8. Run `npm run deploy`. Open `https://YOUR-WORKER.workers.dev/admin`, click **Login with Discord**. Only the configured Discord user ID will be authorized.
9. In `site/index.html`, replace `https://REPLACE-WITH-YOUR-WORKER.workers.dev` with the actual Worker URL.
10. Commit `site/index.html` as `index.html` at the root of your GitHub Pages repository. In GitHub repository Settings → Pages, deploy from `main` / root. Open the site, verify roster, drag bookmarklet to bookmarks.

## Security notes

- The **Discord client secret** must be stored as a Worker secret, never in GitHub Pages or committed to Git.
- Use your **Discord user ID** (Developer Mode → right-click yourself → Copy User ID), not a server ID or bot ID.
- Public visitors can read the roster, but cannot modify it. Mutations require an authorized Discord login and same-origin checks.
- OAuth state is checked; session tokens are stored as hashes in D1 and sent in Secure HttpOnly SameSite=Lax cookies. Sessions expire after 7 days.
- The public GitHub Pages site and Worker admin panel are intentionally on different domains. The admin panel lives at the Worker URL to avoid cross-site-cookie issues.
- Never put Steam credentials, session cookies, or Discord tokens into the website.
- This uses unofficial Steam Community endpoints; actions can fail or change, and Steam may block bookmarklets under browser security policy. Test with a small roster first.
- GitHub Pages cannot hide the public player list. Only admin editing is private.
- Cloudflare free tiers have quotas; 24/7 uptime is not guaranteed.

## Discord login vs Discord bot

This package implements **Discord OAuth login** to authorize the admin. It does not require a Discord bot process or a paid 24/7 host. It does not implement Discord slash commands.
