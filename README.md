# Halo2(PSE) client for kzg ceremony

This client will generate proofs for contribution.

Before you use this client, params for this Halo2 circuit should be generated. If not, you should generate params before you try it.
```
cargo test -r --lib circuit_g1_mul::test_write_params -- --nocapture
cargo test -r --lib circuit_g2_mul::test_write_params -- --nocapture
```
This will generate two params for circuit, and **will be only in test**!

## How to contribute

### Step 1 - Get your `session-id` 

- Open the [request_link](https://seq.ceremony.ethereum.org/auth/request_link) endpoint in your browser.
- You'll be presented with two links, one for Ethereum address participation and one for GitHub account participation. Open the corresponding link and follow the explained steps.
- In the end, you'll receive a JSON that has a `session_id` field with a value _similar to_ `504d898c-e975-4e13-9a48-4f8b95d754fb`. This string is your `session-id`, copy it to your clipboard.

Note that this step of the process is done on an external website unrelated to this ceremony client. This website is related to the sequencer which all clients target and is managed by the Ethereum Foundation.

If you got an error trying to get your `session-id`, it could be one of the following ones:
- `AuthErrorPayload::UserCreatedAfterDeadline`: your Ethereum address isn't matching the sequencer minimal conditions. Your Ethereum address should have sent at least 3 transactions at block 15537393. If that isn't true, you can't participate with this Ethereum address.
- `AuthErrorPayload::InvalidAuthCode`: your request link got stale. Start the login process from scratch.
- `AuthErrorPayload::UserAlreadyContributed`: you can only contribute once per GitHub account or Ethereum address.

### Step 2 - Contribute!

First, compile this repo.
```
cargo build -r
```
Optionally, you can first check the status of the lobby:
```bash
$ ./target/release/cmd status
Sequencer status:
  Lobby size: 0
  NumContributions: 108932
  SequencerAddress: 0xfAA3A87713253D44E33C994556f7727AC71937f0
```
This can provide some context around how many people are waiting for their turn to contribute and a sense of waiting times.

Contribute to the ceremony by running. The random string should be more than 64-byte.
```
$ ./target/release/cmd contribute --session-id <session-id> --rand <random string>
```
This will take long time, because of generating many halo2 proofs.
