---
wizard: 0.2
id: profiles
name: Profiles
type: view
category: app
version: 0.6.0
summary: Your phone Wizard ID is you; this Wizard receives for you. Add friends by ID and share your look, build and App Store apps.
tags: [communication]
license: GPL-3.0-only
source: https://github.com/oscarhenrycollins/profiles
runtime:
  kind: runtipi
  config: runtipi/config.json
  compose: runtipi/docker-compose.yml
api:
  port: 8836
  path: /api
  spec: openapi.json
mcp:
  path: /mcp
  port: 8836
  transport: streamable-http
skill: skill/SKILL.md
view:
  path: /
  port: 8836
  source:
    path: web
    build: python3 app/build_view.py
    dist: web
provides:
- profiles
system: false
uses: []
needs: []
health: /healthz
---

# Profiles

Your Wizard profile has three parts, and each one is Private, Friends or Everyone:

- **Build**: your version of Wizard, with every change of your own. Friends can **try it on**: it runs beside your own Wizard with your chats and apps, and Stop ends it. Your Wizard is never changed.
- **Look**: your skin and your own touches to it. Friends can **wear it**; one tap puts yours back.
- **Apps**: the App Store apps you have, and which ones you use a lot. Apps you build yourself never show; putting an app in the App Store is what makes it public.

Nothing is shared until you choose Friends or Everyone. Changes to visible parts share automatically; there is no Publish button.

Your phone's Wizard ID (npub) is you. **Claim this Wizard** asks your phone to sign a device list (kind 30078, `d=wizard-devices`, about 90 days). It preserves other devices. This Wizard keeps its existing key as a revocable inbox and profile-sharing device; it never receives your phone's private key. Its public device profile says "<name>'s Wizard" and links to your person ID.

Adding a friend or accepting a request asks the phone to encrypt and sign the friend seal. This Wizard gift-wraps it with a throwaway key for the resolved inbox. Profile copies are automatically encrypted and box-signed with the owner p-tag; only current profile-role devices are trusted. Claims update friend pairs without re-adding; revocations stop encryption to removed inboxes.

Until claimed, a stock installation still works as **<name>'s Wizard (unclaimed)**, never as a person. On desktop without a phone ID the screen offers phone setup. Claimed installations never silently fall back to box signing. Legacy peers receive phone-signed requests; their replies may be addressed to the phone. Use **Open N sealed requests** or **Open sealed profile on your phone** to decrypt transition copies explicitly. The validated plaintext is not retained. Nobody connects to your Wizard; sharing uses Nostr relays.
