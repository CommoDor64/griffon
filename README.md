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
cargo run --bin griffon-cli <hex-plaintext> <hex-key>
```

Example:

```bash
cargo run --bin griffon-cli 0x0123456789ABCDEF 0x133457799BBCDFF1
```

Opens a terminal UI that steps through the full cipher trace. Use `←`/`→` (or `h`/`l`) to move between steps and `q` to quit.

## Library usage

```rust
use griffon::canonical_builder;

let mut des = canonical_builder().build(key);
des.start(plaintext);
for _ in 0..16 {
    des.next_round();
}
des.finalize();

let trace = des.get_history(); // full step-by-step trace
let ciphertext = des.state.to_u64();
```

`canonical_builder()` wires up the standard NIST DES functions. You can replace any of them via the builder to experiment with modified ciphers and observe the effect on the trace.

## TODO
- ~DES abstraction + DES nist implementation~
- ~PoC CLI parse + tui presentation
- AES abstraction + AES nist implementation - IN PROGRESS
- MD5 abstraction + MD5 nist implementation