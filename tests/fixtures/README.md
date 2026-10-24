# Stock Profiles interoperability fixture

`stock_server.py` is the **unchanged** `app/server.py` from
https://github.com/oscarhenrycollins/profiles at
`589f810a0ed2f301726e94e3e269a1a4400d2225` (0.5.1).
SHA-256: `9cf2a22ce98f0f975c40b788d6af769f747db178737bf4d4f09908cd1df76eaf`.
It remains under this repository's GPL-3.0-only license.

It is loaded into a separate disposable DATA directory with an in-process fake
relay, never installed or pointed at an owner's existing state. The regression
executes the stock unwrap, add, encrypted-share and request-poll implementations:
Miguel receives James's **owner-signed** request, adds back the owner npub, and
James reads Miguel's stock phone-addressed encrypted profile via the phone-only
decrypt fallback. Do not rewrite this fixture to match the new implementation.
