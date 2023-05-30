mod circuit_utils;
mod circuits;
mod client;
mod serialization;

use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::{bls12_381, bn256};

use crate::serialization::BatchTranscript;
use circuits::{circuit_g1_mul, circuit_g2_mul};
use client::prover;

#[derive(StructOpt)]
enum Command {
    /// Create proofs
    Prove {
        tau0: String,
        tau1: String,
        tau2: String,
        tau3: String,
    },
    /// Verify proofs
    Verify,
}

#[derive(StructOpt)]
#[structopt(name = "kzg ceremony")]
struct Opt {
    #[structopt(subcommand)]
    command: Command,
}

#[derive(Serialize, Deserialize)]
struct Proof(Vec<(Vec<Vec<u8>>, Vec<Vec<u8>>)>);

fn main() {
    let opt = Opt::from_args();

    match opt.command {
        Command::Prove {
            tau0,
            tau1,
            tau2,
            tau3,
        } => {
            prover::prove(vec![tau0, tau1, tau2, tau3]);
        }
        Command::Verify => {
            prover::verify();
        }
    }
}
