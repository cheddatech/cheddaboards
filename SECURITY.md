# Security

CheddaBoards runs live games, so reports are taken seriously and acted on quickly.

## Reporting a vulnerability

Email **info@cheddaboards.com** with "Security" in the subject. Include:

- What you found and where (file, method, route)
- Steps to reproduce, or a proof of concept
- The version or tag you tested against

You'll get a reply within 3 working days. Please give us time to ship a fix before posting publicly; we'll credit you in the changelog if you'd like.

## Scope

- This canister (`cheddaboards_v2_backend`) and its published mirror
- The hosted API at api.cheddaboards.com and the dashboard at cheddaboards.com
- The official SDKs (Godot, Unity)

Out of scope: games built on CheddaBoards (report those to the game's developer), and third-party services we depend on.

## Supported versions

Only the latest tagged release is supported. Security fixes are not backported, so self-hosters should track the latest tag.

## Disclosure history

Fixed issues are recorded in [CHANGELOG.md](CHANGELOG.md) under a "Security" heading, with the affected versions and whether any exploitation was found.