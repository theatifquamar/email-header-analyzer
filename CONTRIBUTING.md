# Contributing to Email Header Forensics

Thanks for considering a contribution. This project is intentionally small
and single-purpose (a client-side email header analyzer with no backend),
which keeps most contributions approachable even without deep React
experience.

## The two easiest, highest-value contributions

You don't need to touch any analysis logic or UI code to help with either
of these — they're plain data additions:

### 1. Add an email provider to the recognition registry

`src/engine.js` contains a `PROVIDERS` array — hostname patterns for ESPs
(SendGrid, Mailchimp, Amazon SES, …) and secure email gateways (Proofpoint,
Mimecast, …) that the analyzer uses to distinguish expected routing from
suspicious forwarding. If you know a provider that isn't covered:

```js
{ rx: /(^|\.)example-esp\.net$/i, name: "ExampleESP (ESP)", kind: "esp" },
```

Open an issue using the **"Add an email provider"** template (or a PR
directly if you're comfortable) with the provider name, the hostname
pattern it uses in `Received`/`Authentication-Results` headers, and
whether it's an ESP, a secure email gateway, or a mailbox provider.

### 2. Add or improve a glossary term

`src/pages/Glossary.jsx` contains a `TERMS` array — plain-language
definitions of every email-security term the analyzer surfaces. If a term
is missing, unclear, or could use a better example, use the **"Add/improve
a glossary term"** issue template or open a PR.

## Other contributions

Bug reports, UI/UX suggestions, documentation fixes, and new analysis
heuristics are all welcome via regular issues and PRs. For anything larger
than a small fix (a new evidence check, a new page, a scoring-weight
change), please open an issue first to discuss the approach — scoring
weights in particular should be changed deliberately, since they affect
every existing report's reproducibility.

## Development setup

```bash
git clone <this repo>
cd <this repo>
npm install
npm run dev       # local dev server
npm test          # run the Vitest suite (must pass before a PR is merged)
npm run build     # production build, same as CI
```

## Before opening a PR

- `npm test` passes locally.
- If you changed `src/engine.js`, add or update a test in
  `src/__tests__/engine.test.js` covering the change — this is what gives
  the scoring logic regression protection as the project grows.
- If you changed anything visual, a quick description or screenshot in the
  PR helps review move faster.
- Keep the privacy model intact: no new network destination without it
  being a) optional, b) clearly disclosed in the Policy page, and c) added
  to the Content-Security-Policy `connect-src` allow-list in every
  deployment config (`index.html`, `vercel.json`, `netlify` `_headers`,
  `docker/nginx.conf`) — not just one of them.

## Code of conduct

Be respectful and constructive. This is a security tool built for a
community that includes people investigating real, sometimes stressful
incidents — keep that context in mind in discussions.

## Questions

Open a discussion/issue, or reach the maintainer via
[LinkedIn](https://www.linkedin.com/in/theatifquamar/).
