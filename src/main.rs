mod circuit_utils;
mod circuits;
mod client;
#[macro_use]
mod serialization;

use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::{bls12_381, bn256};

use crate::client::contribute::contribute_ceremony;
use crate::client::status::status;
use crate::client::verify_transcript::verify_transcript;
use crate::serialization::BatchTranscriptJson;
use circuits::{circuit_g1_mul, circuit_g2_mul};
// use client::prover;

#[derive(StructOpt)]
#[structopt(name = "kzg ceremony", about = "KZG Ceremony Command Line Tool")]
enum Command {
    /// Get the current status
    #[structopt(name = "status")]
    Status,

    /// Contribute to the ceremony
    #[structopt(name = "contribute")]
    Contribute {
        /// Session ID
        #[structopt(long = "session-id", short = "s")]
        session_id: String,

        /// random bytes
        #[structopt(long = "rand", short = "r")]
        randomness: String,
    },

    /// Pulls and verifies the current sequencer transcript
    #[structopt(name = "verify_transcript")]
    VerifyTranscript,
}

#[derive(Serialize, Deserialize)]
struct Proof(Vec<(Vec<Vec<u8>>, Vec<Vec<u8>>)>);

fn main() {
    let opt = Command::from_args();

    match opt {
        Command::Status => {
            status();
        }
        Command::Contribute {
            session_id,
            randomness,
        } => {
            contribute_ceremony(session_id, randomness);
        }
        Command::VerifyTranscript => {
            verify_transcript();
        }
    }
}
