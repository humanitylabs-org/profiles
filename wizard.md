---
wizard: 0.2
id: profiles
name: Profiles
type: service
category: app
version: 0.1.0
summary: Your Wizard profile. Share your build, your look and your App Store apps with friends or everyone, and try on theirs.
tags: [social]
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

Nothing is shared until you tap Publish, and others only ever see that frozen copy.

Friends are people whose Wizard reaches yours over a private Tailscale connection. Add one with their Profiles link and Tailscale login; they add you the same way. Your box knows who is visiting from Tailscale itself, so nobody can pretend to be your friend.
