# Security policy

Veilway is used on censored and hostile networks. A vulnerability here can expose what someone is doing, or that they are using the software at all, so reports are taken seriously and handled in private.

## Reporting a vulnerability

Report it through GitHub's private form:

https://github.com/veilway-project/veilway/security/advisories/new

The report is visible only to you and the project maintainers. The project has no security email address yet, so this form is the only private channel.

**Do not open a public issue, pull request or Discussions thread for a vulnerability**, and do not post details in a commit message. If you are not sure whether something is a security problem, report it privately anyway.

Please include what you can of:

- the version or commit, the operating system, and which part is affected (server, bridge, desktop app);
- what an attacker needs (network position, a valid account, a crafted file) and what they gain;
- steps or a proof of concept that reproduces it.

Remove real server addresses, keys, passwords and subscription links before you send anything. Use `example.com` and addresses from `192.0.2.0/24`, `198.51.100.0/24` or `203.0.113.0/24` in examples.

## What happens next

| Step | Time |
|---|---|
| We confirm that we received the report | within 7 days |
| We tell you whether we can reproduce it and how serious we think it is | within 14 days |
| Fix released for a confirmed vulnerability | as fast as it can be done properly; we aim for 30 days and tell you if it will take longer |

We keep you informed while the fix is in progress, agree a disclosure date with you, and publish an advisory when the fix is out. You are credited in the advisory and the release notes under the name you choose, or not at all if you prefer. Please give us up to 90 days before publishing details yourself; if users are already being attacked, tell us and we will move faster.

There is no paid bounty.

## Supported versions

Veilway is pre-1.0. Only the latest release and the `main` branch receive security fixes.

## Scope

In scope: everything in this repository, including the `veilway` binary, the library crates, the desktop app, the update mechanism, the release artifacts and the patched code in `vendor/ipstack`.

Things we particularly want to hear about:

- a way to tell Veilway traffic from ordinary traffic, or to confirm a server by probing it;
- traffic or DNS leaving a client outside the tunnel;
- one peer reaching or observing another peer's traffic;
- crashes, memory exhaustion or code execution from network input, config files, subscriptions, themes or provider content;
- anything that lets an update or a download be replaced.

Vulnerabilities in third-party dependencies are best reported upstream first. Tell us too if Veilway's use of the dependency makes the problem exploitable.

## Verifying a release

The `veilway-<target>` binaries of a tagged release are signed with [minisign](https://jedisct1.github.io/minisign/). Each asset has a `.minisig` file next to it, and its trusted comment names the tag and the asset. No release has been published yet.

```
minisign -Vm veilway-x86_64-unknown-linux-musl -P RWQiodKlFCiJ3bkZD3ojKV7AYyTYf3F5x/XY8upWvpSFTVm3O2cNRbrV
```

The desktop installer is signed with a separate key that the app's updater checks before it installs anything.

## Status of the obfuscation layer

The tunnel itself is WireGuard, through the boringtun implementation, with its cryptography unchanged. The layer around it that makes traffic harder to recognize and block (transports and obfuscation) is **experimental and has not been externally reviewed**. It has had no independent audit. Do not treat it as proven against a capable censor, and do not rely on it alone where being detected has serious consequences. This notice will be updated when a review has taken place.

## Good faith

We will not pursue or support legal action against anyone who finds and reports a problem in good faith, stays within their own systems and accounts or ones they have permission to test, and does not access other people's data or disrupt their service.
