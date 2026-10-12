# Fuzzing

`config` feeds bytes to `Config::parse`. A config that parses is validated with the shadow check on, serialized back to JSON, parsed again, and must give the same number of validation errors. Needs nightly Rust, so run it in Docker from the repo root:

```
docker run --rm -v "$PWD":/w -v veilway-fuzz-target:/w/fuzz/target -v veilway-fuzz-cargo:/usr/local/cargo -w /w rustlang/rust:nightly sh -c "cargo install cargo-fuzz --locked; mkdir -p /tmp/corpus; cargo fuzz run config /tmp/corpus fuzz/corpus/config -- -max_total_time=300 -dict=fuzz/dict/config.dict -max_len=65536"
```

New inputs go to the first corpus directory (`/tmp/corpus`, lost with the container), so the tracked seeds in `fuzz/corpus/config/` stay as written. To keep a good new input, copy it into the seed directory by hand. A crash is saved under `fuzz/artifacts/config/`; shrink it with `cargo fuzz tmin config <file>`.
