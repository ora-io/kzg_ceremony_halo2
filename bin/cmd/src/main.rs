#[macro_use]
mod client;

use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use kzg_ceremony_circuit::halo2_proofs::pairing::bn256::Fr;
use kzg_ceremony_circuit::halo2_proofs::pairing::group::Curve;
use kzg_ceremony_circuit::halo2_proofs::pairing::{bls12_381, bn256};

use client::contribute::contribute_ceremony;
use client::status::status;
use client::verify_transcript::verify_transcript;
use kzg_ceremony_circuit::{circuit_g1_mul, circuit_g2_mul};
use kzg_ceremony_prover::serialization;

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
