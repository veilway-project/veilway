<!--
Thank you for the pull request. CONTRIBUTING.md has the details behind this checklist.
Fixing a vulnerability? Do not open a public pull request. Report it first:
https://github.com/veilway-project/veilway/security/advisories/new
-->

## What this changes

## Why

Link the issue or discussion if there is one.

## How it was tested

Commands you ran, and the systems and networks you tried it on. For anything that touches the tunnel, say whether you tested real traffic through it, not only the unit tests.

## Checklist

- [ ] `cargo test --workspace` passes
- [ ] Tests added or updated for the change, including hostile input for any parser
- [ ] No formatter was run (`rustfmt`, `cargo fmt`, prettier) and the diff only touches lines this change needs
- [ ] Code follows the style in CONTRIBUTING.md
- [ ] No real server addresses, keys, passwords or subscription links in code, tests, logs or screenshots
- [ ] UI changes: screenshots attached in dark and light, English and Persian
- [ ] Docs updated or a follow-up opened in `veilway-docs`, if behaviour or config changed
- [ ] I have signed the CLA, or will when the bot asks

## Notes for the reviewer

Anything you are unsure about, or trade-offs you made.
