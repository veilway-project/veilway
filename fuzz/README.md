# Fuzzing

`config` feeds bytes to `Config::parse`. A config that parses is validated with the shadow check on, serialized back to JSON, parsed again, and must give the same number of validation errors. Needs nightly Rust, so run it in Docker from the repo root:

```
docker run --rm -v "$PWD":/w -v veilway-fuzz-target:/w/fuzz/target -v veilway-fuzz-cargo:/usr/local/cargo -w /w rustlang/rust:nightly sh -c "cargo install cargo-fuzz --locked; mkdir -p /tmp/corpus; cargo fuzz run config /tmp/corpus fuzz/corpus/config -- -max_total_time=300 -dict=fuzz/dict/config.dict -max_len=65536"
```

`packet` feeds bytes to the header parser every decrypted packet goes through (`engine::netstack::parse`) and to the two answers the node writes itself, the TCP reset and the echo reply. A packet that parses must have its upper-layer header inside it, and an echo reply must parse and go back to the sender. It needs no seeds or dictionary: replace `config` with `packet` in the command above and drop the `fuzz/corpus/config` and `-dict` arguments.

`dns` feeds bytes to the two readers of the node's resolver (`engine::dns::query` and `engine::dns::response`), which see every DNS message from a tunnel and from an upstream server. A query that is read must give REFUSED and SERVFAIL answers that read back as answers to it. Replace `config` with `dns` in the command above, drop the `-dict` argument and use `-max_len=4096`.

New inputs go to the first corpus directory (`/tmp/corpus`, lost with the container), so the tracked seeds in `fuzz/corpus/config/` stay as written. To keep a good new input, copy it into the seed directory by hand. A crash is saved under `fuzz/artifacts/config/`; shrink it with `cargo fuzz tmin config <file>`.
