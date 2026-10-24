# Owner identity — 0.6.0

Implement the locked WIZARD_ID.md two-key model (wizard-os main, decision 94).
The server stores only its existing device secret; owner encryption and signatures go through the shared shell client.
No install, live data access, deployment, or public relay use in tests.

Reuse:
- identity transport: REUSE WizardApp.identity from the shared `/wizard-os-home/core/app-client.js` (parallel shell change); domain wrapper only, no second postMessage transport.
- app appearance: REUSE existing Wizard UI kit, `--wz-*` tokens and shared WizardApp.theme.
- nested Back: REUSE WizardApp.back; preserve existing fallback for shells predating the facade.
- friend identity: NEW domain-only pure `app/identity_resolve.py`, movable to a shared identity library; not a platform UI implementation.
Visual: existing ID card/button/section components, no new artwork.

Acceptance:
- Verify signed, newest device lists, expiration, roles, revoked timestamps; never revive an old list when a newer list expires.
- Resolve friends to person keys and inbox devices, re-key claims without re-adding and stop encrypting to revoked devices.
- Exact prepared-event verification for claim and friend seals. Owner cannot silently fall back to box signing.
- Legacy stock peer receives owner seal; its replies and profile copies addressed to the phone require explicit phone decryption, not a server owner key.
- Offline fake-relay Python tests, mocked shared-client JS flow tests, existing backup browser checks on disposable state, packaging/source consistency.

Release boundary: push feature/owner-identity to humanitylabs-org/profiles; upstream PR and shell/native integration/device QA remain with the parent owner.
