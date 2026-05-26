<img src="./griffon.png" alt="griffon logo" style="height: 800px; width:800px;"/>

# griffon

A symmetric cipher suite built for learners (never for real-world usage). It lets you track, trace and visualize every step a cipher makes, showing its state, key scheduling, etc. Perfect as a "calculator" for symmetric cryptography courses where tracking state change across subtitutions and permutation often happens.
## Test

```bash
cargo test
```
Runs the NIST test vector to verify the canonical DES produces the correct ciphertext.

## Run

```bash
cargo run --bin griffon-cli <hex-plaintext> <hex-key> [OPTIONS]
```

Example:

```bash
cargo run --bin griffon-cli 0x0123456789ABCDEF 0x133457799BBCDFF1
```

Prints a step-by-step DES trace to stdout. Run with `--help` for full usage. Available options:

| Flag | Default | Description |
|------|---------|-------------|
| `--format hex\|bin` | `hex` | Display values in hex or binary |
| `--rounds N` | `16` | Number of Feistel rounds |
| `--skip expand,key-mix,substitute,permute` | _(none)_ | Omit selected f-function sub-steps from output |
| `--export FILE` | _(none)_ | Write trace as JSON to a file; use `-` for stdout |


Example — binary format, skip expand/permute sub-steps:

```bash
cargo run --bin griffon-cli 0x0123456789ABCDEF 0x133457799BBCDFF1 \
  --format bin --skip expand,permute
```

Example — export trace as JSON:

```bash
cargo run --bin griffon-cli 0x0123456789ABCDEF 0x133457799BBCDFF1 --export trace.json
```

Example output (truncated to first two rounds):

```
=== DES Trace ===
Plaintext:  0x0123456789abcdef
Key:        0x133457799bbcdff1
Ciphertext: 0x85e813540f0ab405

[ 1 / 18]  Initial Permutation
  input:   0x0123456789abcdef
  output:  0xcc00ccfff0aaf0aa

[ 2 / 18]  Round  1
  left:      0xcc00ccff
  right:     0xf0aaf0aa
  round_key: 0x1b02effc7072
  f-steps:
    expand      0x7a15557a1555
    key_mix     0x6117ba866527
    substitute  0x5c82b597
    permute     0x234aa9bb

[ 3 / 18]  Round  2
  left:      0xf0aaf0aa
  right:     0xef4a6544
  round_key: 0x79aed9dbc9e5
  f-steps:
    expand      0x75ea5430aa09
    key_mix     0x0c448deb63ec
    substitute  0xf8d03aae
    permute     0x3cab87a3
...
```

## Library usage

```rust
use griffon::canonical_builder;

let mut des = canonical_builder().build(key);
let (ciphertext, trace) = des.encrypt(plaintext);
```

`encrypt` returns the ciphertext and a `DESTrace` (a `Vec<DESTraceEntry>`) with one entry per stage: the initial permutation, each Feistel round (including the full f-function sub-step trace), and the final permutation.

`canonical_builder()` wires up the standard NIST DES functions. You can replace any of them via the builder to experiment with modified ciphers and observe the effect on the trace.

## TODO
- ~DES abstraction + DES nist implementation~
- ~PoC CLI parse + tui presentation
- AES abstraction + AES nist implementation - IN PROGRESS
- MD5 abstraction + MD5 nist implementation