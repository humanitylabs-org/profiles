---
name: profiles
description: Use when the owner asks about his Wizard profile, friends, or sharing his build, skin or apps.
version: 0.1.0
author: Hermes Agent
license: GPL-3.0-only
platforms: [linux, macos]
metadata:
  hermes:
    tags: [profiles, friends, sharing]
    related_skills: []
---
# Profiles

The owner's Wizard profile: his build (his version of the Wizard shell), his look (skin plus his own CSS touches) and his App Store apps. Each part is Private (default), Friends or Public. Identity is a Nostr ID (npub) the app keeps for this Wizard; friends are added by npub alone. Sharing goes through public Nostr relays (public parts signed, friends' parts NIP-44 encrypted per friend, requests NIP-59 gift-wrapped); nobody connects to the owner's Wizard. Changes share automatically, no Publish step. Trying on a build is friends-only.

- `profile_get` reads visibility, the published snapshot, friends and requests. `profile_preview` with `as: friend|public` shows exactly what others see.
- `profile_set_visibility` changes one part. Only when the owner asked. Sharing is a privacy decision; never widen it on your own.
- `friends_list` and `friend_profile` (friend id) read friends and what a friend shares.
- Publishing, adding friends, wearing a look and trying on a build are done by the owner in the Profiles screen. Point him there instead of doing it for him.

Rules the app enforces (don't work around them): an app is shared only if the Wizard App Index lists its public repo, so local and private apps never show; a build is shared only if its exact commit is public shell code; others see a frozen snapshot from his last Publish, never live state; a friend's answer is re-checked on this box before it is shown.
