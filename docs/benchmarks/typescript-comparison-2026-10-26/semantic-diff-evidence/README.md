# Isolated JavaScript semantic differential

This evidence compares the current-checkout TypeScript parser with a Rust
semantic harness over 21 synthetic fixtures in `import`, `require`, and
`compiler-dependent` modes. Each mode compared 21 entries and reported zero
differences. It is diagnostic evidence, not application-wide parity.

The fixture manifest is [`manifest.json`](manifest.json), and all referenced
files are included here. Their SHA-256 values are in
[`fixture-digests.txt`](fixture-digests.txt). The copied Rust harness source is
[`src-main.rs`](src-main.rs); its SHA-256 is
`e09912e3b10dcbd6f49234b20228f4354ccb7177de81f33157e9aeed25dc65e4`.

The recorded release comparison used the prebuilt binary described by
[`provenance.json`](provenance.json) and ran:

```sh
cd /tmp/rea-semantic-diffharness
REA_RUST_SEMANTIC_BIN=/tmp/rea-semantic-diffharness/js-full-semantic-diff-release ./run-diff.sh
```

The comparator ignores only `micros`; the three `diff-*.json` files contain the
bounded comparison results. The original isolated Cargo workspace, its
`Cargo.toml`, dependency checkout, and build output were temporary and are not
included here. The source copy and recorded hashes identify that build; they do
not make this directory a standalone Cargo project.

The TypeScript parser is from the current checkout at
`dist/domain/javascript`, SHA-256
`54355ad94379cf8f29488ec14e0439c2260e1ffd0f1686e168fd757e97779955`. This is
separate from the frozen full-application TypeScript baseline in the cross-app
attempts.
