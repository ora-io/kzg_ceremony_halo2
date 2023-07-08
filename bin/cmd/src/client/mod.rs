pub mod contribute;
pub mod message;
pub mod offline_prove;
pub mod request;
pub mod status;
pub mod verify_proofs;
pub mod verify_transcript;

const SEQUENCER: &str = "https://seq.ceremony.ethereum.org";
// const SEQUENCER: &str = "http://127.0.0.1:3000";
const MIN_RANDOMNESS_LEN: usize = 64;
