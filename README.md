# Halo2(PSE) client for kzg ceremony

This client will generate proofs for contribution.

Before you use this client, params for this Halo2 circuit should be generated. If not, you should generate params before you try it.
```
cargo test -r circuit_g1_mul::test_circuit -- --nocapture
cargo test -r circuit_g2_mul::test_circuit -- --nocapture
```
This will generate two params for circuit, and **will be only in test**!

## How to use

### Prove

Use the following command to generate proofs. `tau_1`, `tau_2`, `tau_3`, and `tau_4` are your random number(toxic waste).

```
cargo run -r prove tau_1 tau_2 tau_3 tau_4
```

### Verify 

Rename your new transcripts as `Transcripts.json`. Run the following command.

```
cargo run -r verify
```
