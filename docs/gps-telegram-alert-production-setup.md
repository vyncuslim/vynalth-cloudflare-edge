# GPS Telegram alerts — production secret setup and verification

## Meaning of /__shield/gps/status

`telegramAlerts.enabled: true` means the feature flag is on.
`telegramAlerts.configured: true` means the **currently running Edge Worker** has (1) a syntactically valid Telegram bot token, (2) a syntactically valid chat destination, and (3) read/write access functions for the `CONSENT_KV` binding.

It does **not** mean Telegram has accepted any message or a user has received/read it. Only a real successful `sendMessage` acknowledgment with `ok: true` and `result.message_id` provides evidence that the Telegram API accepted a particular message.

## Operator setup (Cloudflare secrets; no secrets in Git)

Worker: `vynalth-cloudflare-edge` **not** the old School Policy Worker or a Vercel project.

In Cloudflare Dashboard → Workers & Pages → `vynalth-cloudflare-edge` → Settings → Variables and Secrets, add two **Secret** entries:

- `TELEGRAM_BOT_TOKEN` = the existing token issued by Telegram BotFather for the intended bot (never a sample/test token).
- `TELEGRAM_CHAT_ID` = the numeric ID of the personal chat/group/channel to which this bot can send messages.

These shared names configure **both** sitewide `EDGE_TELEGRAM_ALERTS_ENABLED=true` and GPS `GPS_TELEGRAM_ALERTS_ENABLED=true`. Alternatively, GPS supports `GPS_TELEGRAM_BOT_TOKEN` and `GPS_TELEGRAM_CHAT_ID` but those configure GPS separately, not necessarily the Edge alerts.

Select **Deploy** to apply the secret bindings; confirm you are updating the existing production Worker. Do not put credentials in `wrangler.toml`, GitHub Actions logs/issues, commits, chat messages, or `[vars]` in Git. If both secret names already exist, verify their format/target and that the bot was added to the chat; do not overwrite an unknown working bot or rotate credentials unnecessarily.

The repo declares `CONSENT_KV` in `wrangler.toml`. Confirm the same binding is present on the live production Worker. The GPS status endpoint does not reveal which requirement is missing.

### Optional Wrangler CLI (use only on an authenticated owner machine)

```sh
npx wrangler secret list --name vynalth-cloudflare-edge
# If a secret name is missing, add it *interactively*, never in shell history:
npx wrangler secret put TELEGRAM_BOT_TOKEN --name vynalth-cloudflare-edge
npx wrangler secret put TELEGRAM_CHAT_ID --name vynalth-cloudflare-edge
```

`wrangler secret put` creates/deploys a new Worker version. Prefer Dashboard if Cloudflare Workers Builds owns production deploys, and review deployment before changing secrets.

### Real verification checklist

1. On **the actual production hostname**, GET `https://vynalthai.com/__shield/gps/status`. Require `telegramAlerts.enabled=true` and `configured=true`.
2. Confirm the target Telegram chat has started the bot or granted it send permissions as appropriate. A chat ID and bot token can be syntactically valid while Telegram rejects their pairing.
3. Perform a **consented and authorized** integration test from an approved test environment that produces an actual `CAMPUS_BOUNDARY_UNCERTAIN` or `CAMPUS_RESTRICTED` verdict, without falsifying location or disturbing real users.
4. Verify the resulting `sendMessage` response has HTTP 200, JSON `ok: true`, and `result.message_id`, and that the intended chat actually displays the matching request ID/time. Never log the API URL (it contains the token), raw IP, GPS coordinates, cookies, or credentials.
5. Confirm that a rejected/unconfirmed send does not create a cooldown; the next valid alert must be eligible. Successfully acknowledged events retain the existing per-client/global cooldown (900s/60s).
6. Verify general sitewide HTTP 4xx/5xx separately via the independent Edge Telegram pipeline. GPS notifications currently cover only the two campus-denial events; neither pipeline guarantees that **all** HTTP 200 requests produce Telegram messages.

## Important

GitHub automated tests and Wrangler dry-runs do **not** provision production secrets, deliver Telegram messages, or establish chat receipt. Mark production delivery as verified only with an independently observed Telegram response **and** recipient evidence.
