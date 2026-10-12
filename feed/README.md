# Advisory feed

`advisories.json` is the list of MCP-related advisories published to AI-BOM users between releases.

- Add or edit entries here (same shape as `src/vulns/advisories.ts`) and merge to `main`.
- The `advisory-feed` workflow signs the file with the Ed25519 key in the `AI_BOM_FEED_KEY` secret and uploads `advisories.json` + `advisories.json.sig` to the rolling `advisories` release.
- Clients verify the signature with the public key built into `src/feed/index.ts`, refuse older feeds than the one they have, and fall back to the bundled list if anything is off.

One-time setup: `npm run feed:keygen`, paste the public key into `src/feed/index.ts`, and add the printed secret to the repository's Actions secrets. Keep the private key file out of the repository.
