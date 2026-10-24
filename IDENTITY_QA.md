# Owner identity 0.6.0 — verification

## Implemented

- Phone owner npub identifies the person. Existing Wizard secret remains a device/inbox key; no owner private key or ECDH material reaches the app server.
- Pure, transport-independent `app/identity_resolve.py`: verified current device lists, reciprocal owner links, role checks, deterministic replacement, expiration and revocation cutoffs.
- Prepared exact owner events, single-use ten-minute approvals, signature verification, recipient re-resolution and relay acknowledgement before committing a claim/request.
- Owner-created NIP-44 friend seal; box-created throwaway gift wrap. Adds and acceptances share this flow; claimed owners cannot downgrade to device signing.
- Automatic box-signed per-friend shares target resolved inboxes and carry owner p-tags. Friend and request records re-key to persons while retaining stable friend IDs. Unclaimed peers cannot present themselves as people.
- Owner-addressed gift wraps queue for explicit phone opening. Stock phone-encrypted profile copies have a separate explicit phone-decrypt path, validated again by the server without retaining plaintext.
- Inline package includes the resolver module and its direct-script import path. Version, OpenAPI, app skill and manifest updated. No live app installation, restart or existing owner state accessed.

## Executed tests

| Command | Result |
|---|---|
| `python3 -m unittest discover -s tests -p 'test_*.py' -v` | **34 passed**; in-process fake relay, real disposable Schnorr/NIP-44 keys |
| `node --test tests/owner-identity.cjs` | **12 passed**; mocked bridge, denial and no-downgrade paths, actual facade sign argument shape |
| `python3 tests/run_browser.py` on the browser worker with Playwright/Chrome and `PROFILES_SHARED_CORE` | **35 existing identity-backup checks + 24 owner flow checks passed**; no browser JS errors |
| `node --check web/app.js` and `node --check web/identity-client.js` | Passed |
| `python tools/check_package.py` using the packaging PyYAML environment | **12 source files equal**, exact inline entry point booted offline; `/healthz` returned `{ok:true, app:profiles, version:0.6.0}` |
| `wam check <checkout>` using the current Builder | **26 rules passed**, no warnings/errors |
| `git diff --check` | Passed |

Browser harness uses the **real shared app-client.js** from wizard-ux PR 452 at
`393c736886bb5c89be35da6930557495d5a10d98` (SHA-256
`cc5a4aae648618d9a83d5ed08bee52882a14db76477884b195588e2837ed0eda`).
Only the parent/native-phone responses and relay are fixtures; phone signing/encryption
use real throwaway cryptography and exercise the production API verification.
The test covers claim, denial/retry, send, explicit sealed-request opening, accept,
legacy labels and nested Back. It switches dark/light Appearance v1 token fixtures
at 390px and 1280px, preserving an unsent form draft and checking overflow.
Phone-width screenshots were inspected for contrast, clipping and hierarchy.
These are protocol appearance fixtures, not a claim of exhaustive real-skin QA.

Shared kit/token files were copied unchanged from Wizard App Manager
`888a61c948bd701f6f2e7cb6fd876795f43fdcc4`.

## Stock interoperability

`tests/fixtures/stock_server.py` is the unchanged upstream 0.5.1 server;
its provenance and checksum are in the adjacent README. The test runs its actual
request unwrap, add-back and profile-share code in separate disposable state:
stock Miguel receives owner-signed James, replies to James's owner npub, and
James opens Miguel's stock encrypted profile with the phone-only fallback.

## New endpoints

- `POST /api/identity/claim/prepare`
- `POST /api/identity/claim`
- `POST /api/friends/prepare`
- `POST /api/friends/seal`
- `POST /api/friends/commit`
- `GET /api/identity/pending`
- `POST /api/requests/open`
- `POST /api/friends/{id}/profile/open`

## Release boundary / open questions

- Physical-phone native signing, biometric approval and the eventual merged shell build
  still need a device acceptance run. This work does not deploy or alter the owner's live box.
- A stock peer's opaque pair-tag cannot be derived server-side without the phone's
  ECDH key. The transition path scans recent signed author copies (100-event fetch,
  at most 20 trial-decrypt candidates) on explicit user action. A heavily-used legacy
  peer can require a wider/paginated scan; do not export owner conversation keys to solve it.
- Phone decryption binds plaintext to ciphertext. The authenticated browser passes
  plaintext to validation endpoints; the server verifies sender signatures and policy,
  but cannot independently repeat owner decryption. This trust boundary is documented
  in OpenAPI rather than pretending the server has the owner's secret.
- Device-list resolution cannot prove that every public relay has supplied the latest
  event. It caches the newest observed signed evidence and fails closed after expiration;
  ordinary Nostr relay availability/withholding limits remain.
