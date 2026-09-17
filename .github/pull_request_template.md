## What this changes

<!-- The behaviour, not the diff. -->

## Why

<!-- The problem it solves, or the issue it closes. -->

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --lib --bins -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo deny check` — advisories, licences, bans, sources
- [ ] Commits are signed off (`git commit -s`) per the DCO
- [ ] New behaviour has a test that fails without this change
- [ ] If a receipt field was added, it is `Option` + `skip_serializing_if`, so
      existing receipts and their signatures stay byte-identical
- [ ] If the wire format changed incompatibly, `RECEIPT_SCHEMA_VERSION` is
      bumped and the release note says so
