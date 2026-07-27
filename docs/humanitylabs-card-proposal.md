# Humanity Labs placement proposal

## Recommended section

Place **Hermes Tailnet Secret Drop** under:

**Projects → Hosted by you → Humanity Labs apps**

Put it immediately after **Apps Manager**. It is a private Tailnet utility installed on the user's own Hermes machine, not a hosted service, recurring task, or core Hermes patch. The existing **Hermes upgrades** section is for changes to the Hermes runtime itself, so Secret Drop does not belong there.

## Proposed card

**Name:** Hermes Tailnet Secret Drop

**Description:** Give Hermes a private, one-time page for API keys, tokens, passwords, and private URLs—without pasting them into chat.

**Primary action:** Give this prompt to your AI

**Source:** `https://github.com/humanitylabs-org/hermes-tailnet-secret-drop`

**Release ID:** `secret-drop`

**Suggested icon:** a simple keyhole/drop mark matching the current monochrome Tailnet card icons. Proposed asset path: `images/tailnet-secret-drop-icon.svg`.

## Required site changes after approval

- Add the card after Apps Manager in `index.html`.
- Add `copySecretDropPrompt()` using the approved text in `docs/give-this-prompt-to-your-ai.md`.
- Add the public source link.
- Add a `secret-drop` entry to `releases/apps.json` with the reviewed tag, release date, and exact commit.
- Add a privacy-safe preview only if the card design calls for one; it must use a fake label/value and no live request URL or private hostname.
- Verify HTML and inline JavaScript parsing, the actual copy button text, release-catalog JSON, public repo URLs, mobile rendering, and the live custom domain after publication.

Nothing in this proposal has been added to humanitylabs.org or published to GitHub yet.
