English | [فارسی](CONTRIBUTING.fa.md)

# Contributing to Veilway

Thank you for being here. Veilway exists for people on censored and hostile networks, and every bug report, test on a difficult network, translation, documentation fix and patch makes it more useful to them. You do not need to be a Rust expert or to ask for permission first. If something is unclear, that is a gap in this guide, so please tell us.

## Ways to help

- Report a bug, or confirm someone else's on your own network or device.
- Improve the docs or the Persian text. The documentation lives in [veilway-docs](https://github.com/veilway-project/veilway-docs).
- Pick an open issue and say in a comment that you are working on it.
- Review an open pull request. A second pair of eyes on network and parser code is always wanted.

For anything larger than a small fix, open an issue or a Discussions thread before you write the code. It saves you from building something that cannot be merged.

Security problems are the one exception: never report them in public. See [SECURITY.md](SECURITY.md).

## Building and testing

You need a current stable Rust toolchain. Then, from the repository root:

```
cargo test --workspace
cargo build --release --workspace
```

Try the result:

```
target/release/veilway genkey
target/release/veilway run --config config.json
```

A static Linux binary, the way releases are built (needs `cargo-zigbuild`):

```
cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p veilway --bin veilway
```

The desktop app in `apps/desktop` is outside the cargo workspace and keeps its own `Cargo.lock`. It needs `wintun.dll`, which is not stored in the repository:

```
apps/desktop/scripts/fetch-wintun.sh
cd apps/desktop/src-tauri && cargo check
```

`cargo check` works on macOS; on Linux install the Tauri system dependencies first. A full Windows build is produced by the Windows job in CI, so you do not need a Windows machine to send a change to the desktop app.

### Where things are

| Path | What it is |
|---|---|
| `crates/veilway` | The `veilway` binary: `run`, `genkey`, `bridge client`, `bridge relay` |
| `crates/veilway-core` | The server engine: accept loop, isolation rules, per-flow egress, config |
| `crates/veilway-wg` | WireGuard peer handling and the WebSocket relay (`veilway_wg::ws`) |
| `crates/veilway-client` | The client engine and the Windows adapter, route and DNS layer |
| `crates/veilway-proto`, `veilway-transport`, `veilway-api`, `veilway-xray`, `veilway-ffi` | Skeleton crates that later work fills in |
| `apps/desktop` | The Tauri desktop app |
| `vendor/ipstack` | A patched third-party crate. It keeps its upstream style |

## Sending a change

1. Fork the repository and create a branch from `main`.
2. Keep the change to one topic. Two small pull requests are reviewed faster than one large one.
3. Add or update tests for what you changed. Code that parses anything from the network, a subscription, a theme or a config file needs tests with hostile input, not only valid input.
4. Run `cargo test --workspace` before you push.
5. Open the pull request and fill in the template. Say what you tested and on what system.
6. Sign the CLA when the bot asks (once, see below).

Never put real server addresses, keys, passwords or subscription links in code, tests, logs, screenshots or commit messages. Use `example.com` and the documentation ranges `192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24`.

Your commit name and email become public and permanent. If you would rather not publish them, set a pseudonym and your GitHub `noreply` address in git before your first commit. That is entirely fine here.

## Code style

The project has a house style that the common formatters do not produce. **Do not run `rustfmt`, `cargo fmt` or prettier**, and switch off format-on-save in your editor for this repository. A formatted file shows up as a diff of the whole file and cannot be reviewed.

- Tabs for indentation, as the files already use.
- No blank lines inside a function body. Blank lines go between functions.
- Double quotes for strings wherever the language allows a choice.
- One-liners where they fit and stay readable.
- No helper function for something that is used once. Write it in place.
- Comments only where they add context the code cannot show. No comments that repeat the code.
- No trailing whitespace and no whitespace-only lines.
- Spaces after commas. Spaces around operators and `=` in new files (`a == b`, `let x = 1`).
- Some existing files are written without spaces around operators. Keep such a file consistent with itself, and do not reformat lines you are not changing.
- No em dashes and no emoji anywhere: code, comments, docs and UI text.
- Imports stay clean. Do not leave one that is no longer used.
- `vendor/ipstack` keeps its upstream style. Mark every local change there with a comment that names the patch.

If you are unsure, copy the style of the file you are editing.

## The contributor agreement (CLA)

The first time you open a pull request, a bot asks you to sign the agreement in [CLA.md](CLA.md) by replying with one line. You do this once, not per pull request.

Why it exists, in plain words: under an open source licence every contributor still owns the lines they wrote. If the project ever needs to change its licence, for example to move to a newer licence version or to fix a compatibility problem, it would need written consent from every person who ever contributed, including people who can no longer be reached. For a project used on hostile networks, where contributors may have good reasons to disappear, that is a real risk. The CLA solves it up front.

What you agree to:

- You keep the copyright on your work and can use it anywhere else.
- You give the project a permanent licence to use your contribution and to license it under other terms, including terms that are not open source, plus the same patent licence Apache-2.0 contains.
- You confirm the work is yours to contribute.

What the project promises you in the same document: anything already released stays available under the open licence it was released under. A later licence change cannot take released code back.

Some people do not sign CLAs on principle. We respect that. Bug reports, reviews, testing and discussion need no CLA and are just as welcome.

## How credit works

- The copyright line in the project is "The Veilway Authors". That means everyone who has contributed, not one person or company.
- You stay the author of your commits in the git history. If a pull request is squashed, co-authors are kept with `Co-authored-by` lines.
- Contributors are listed in the README, and each release's notes name the people whose work is in it. That includes reports, testing, translation and review, not only code.
- The licence requires anyone who uses the code to keep the copyright notices and the `NOTICE` file, which credits the Veilway contributors. [TRADEMARKS.md](TRADEMARKS.md) stops a fork from presenting the project as its own.

If you want to be credited under a different name, or not listed at all, say so in your pull request.

## Questions

Ask in [GitHub Discussions](https://github.com/veilway-project/veilway/discussions). There is no such thing as a question too basic for it, and you can write in English or Persian. Issues are for bugs and concrete feature requests.

Everyone taking part is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
