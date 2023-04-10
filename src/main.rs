mod assign;
mod circuit_g1_mul;
mod circuit_g2_mul;
mod circuit_utils;
mod context;
mod range_info;
mod serialization;
mod utils;

use halo2_proofs::pairing::bn256::Fr;
use halo2_proofs::pairing::group::Curve;
use halo2_proofs::pairing::{bls12_381, bn256};
use halo2_proofs::poly::commitment::Params;
use std::fs;
use std::fs::File;
use std::io::Write;

use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use crate::circuit_g1_mul::{
    verify_proof as g1_verify_proof, Circuit as G1_Circuit, Instance as G1_Instance,
    ProvingKey as G1_PK, VerifyingKey as G1_VK, LENGTH as G1_LENGTH,
};
use crate::circuit_g2_mul::{
    verify_proof as g2_verify_proof, Circuit as G2_Circuit, Instance as G2_Instance,
    ProvingKey as G2_PK, VerifyingKey as G2_VK, LENGTH as G2_LENGTH,
};
use crate::serialization::BatchTranscript;

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
            prove(vec![tau0, tau1, tau2, tau3]);
        }
        Command::Verify => {
            verify();
        }
    }
}

fn prove(taus: Vec<String>) {
    println!("Proving");

    let old_transcripts: BatchTranscript = pull_transcripts();

    println!("Reading G1 params...");
    let g1_params = fs::read("g1_params.bin").expect("Read G1 params file failed");
    let g1_params = Params::<bn256::G1Affine>::read(&g1_params[..]).expect("Read G1 params failed");
    println!("Building G1 Proving Key..");
    let g1_pk = G1_PK::build(&g1_params);

    println!("Reading G2 params...");
    let g2_params = fs::read("g2_params.bin").expect("Read G2 params file failed");
    let g2_params = Params::<bn256::G1Affine>::read(&g2_params[..]).expect("Read G2 params failed");
    println!("Building G2 Proving Key..");
    let g2_pk = G2_PK::build(&g2_params);

    println!("Generating proofs...");
    let mut proofs = vec![];
    for (transcript, tau) in old_transcripts.transcripts.iter().zip(taus.iter()) {
        let tau = scalar_from_string(tau);
        let pubkey = (bls12_381::G1Affine::generator() * tau).to_affine();

        println!("Processing G1 proofs...");
        let number_g1_powers = transcript.num_g1_powers as usize;
        assert_eq!(number_g1_powers, transcript.powers_of_tau.g1_powers.len());
        assert_eq!(number_g1_powers % G1_LENGTH, 0);
        let number_g1_proofs = number_g1_powers / G1_LENGTH;

        let mut proofs_g1 = Vec::with_capacity(number_g1_proofs);
        for (i, chunk) in transcript
            .powers_of_tau
            .g1_powers
            .chunks(G1_LENGTH)
            .enumerate()
        {
            println!("Generating G1 proof {}...", i);
            let old_points = decode_g1_points(chunk);

            let from_index = i * G1_LENGTH;
            let mut pow = tau.pow_vartime(&[from_index as u64, 0, 0, 0]);
            let mut new_points = vec![];
            for p in old_points.iter() {
                let new_p = p * pow;
                new_points.push(new_p.to_affine());
                pow = pow * tau;
            }

            let g1_circuit = G1_Circuit::<bls12_381::G1Affine, Fr> {
                from_index: Some(from_index),
                tau: Some(tau),
                points: old_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
                _mark: Default::default(),
            };

            let instances = circuit_g1_mul::generate_instance(&G1_Instance {
                from_index,
                pubkey,
                old_points,
                new_points,
            });
            let proof_g1 =
                circuit_g1_mul::create_proofs(&g1_params, g1_circuit, &g1_pk, &instances);
            proofs_g1.push(proof_g1);
        }

        println!("Processing G2 proofs...");
        let number_g2_powers = transcript.num_g2_powers as usize;
        assert_eq!(number_g2_powers, transcript.powers_of_tau.g2_powers.len());
        assert_eq!(number_g2_powers % G2_LENGTH, 1);
        let number_g2_proofs = number_g2_powers / G2_LENGTH;

        let mut proofs_g2 = Vec::with_capacity(number_g2_proofs);
        for (i, chunk) in transcript.powers_of_tau.g2_powers[1..]
            .chunks(G2_LENGTH)
            .enumerate()
        {
            println!("Generating G2 proof {}", i);
            let old_points = decode_g2_points(chunk);
            let from_index = i * G2_LENGTH + 1;
            let mut pow = tau.pow_vartime(&[from_index as u64, 0, 0, 0]);
            let mut new_points = vec![];
            for p in old_points.iter() {
                let new_p = p * pow;
                new_points.push(new_p.to_affine());
                pow = pow * tau;
            }

            let g2_circuit = G2_Circuit::<Fr> {
                from_index: Some(from_index),
                tau: Some(tau),
                points: old_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
                _mark: Default::default(),
            };

            let instances = circuit_g2_mul::generate_instance(&G2_Instance {
                from_index,
                pubkey,
                old_points,
                new_points,
            });
            let proof_g2 =
                circuit_g2_mul::create_proofs(&g2_params, g2_circuit, &g2_pk, &instances);
            proofs_g2.push(proof_g2);
        }

        proofs.push((proofs_g1, proofs_g2));
    }
    let serialized = serde_json::to_string(&Proof(proofs)).expect("Serialize proof failed");
    let mut file = File::create("Proof.json").expect("Create file failed");
    file.write_all(serialized.as_bytes())
        .expect("Write proof failed");
}

fn verify() {
    println!("Verifying");

    let old_transcripts: BatchTranscript = pull_transcripts();

    let new_transcripts = fs::read_to_string("Transcripts.json").expect("should exist");
    let new_transcripts: BatchTranscript =
        serde_json::from_str(&new_transcripts).expect("Deserialize failed");

    let proof_file = fs::read_to_string("Proof.json").expect("should exist");
    let proofs: Proof = serde_json::from_str(&proof_file).expect("Deserialize proof failed");

    println!("Reading G1 params...");
    let g1_params = fs::read("g1_params.bin").expect("Read G1 params file failed");
    let g1_params = Params::<bn256::G1Affine>::read(&g1_params[..]).expect("Read G1 params failed");
    println!("Building G1 Verification Key..");
    let g1_vk = G1_VK::build(&g1_params);

    println!("Reading G2 params...");
    let g2_params = fs::read("g2_params.bin").expect("Read G2 params file failed");
    let g2_params = Params::<bn256::G1Affine>::read(&g2_params[..]).expect("Read G2 params failed");
    println!("Building G2 Verification Key..");
    let g2_vk = G2_VK::build(&g2_params);

    assert_eq!(proofs.0.len(), new_transcripts.transcripts.len());
    for (proof, (old_transcript, new_transcript)) in proofs.0.iter().zip(
        old_transcripts
            .transcripts
            .iter()
            .zip(new_transcripts.transcripts.iter()),
    ) {
        let pubkey = {
            let str = new_transcript
                .witness
                .pot_pubkeys
                .last()
                .expect("Should exist");

            let bytes = hex::decode(&str[2..]).expect("Failed to decode point in hex string");

            bls12_381::G1Affine::from_compressed(&bytes.try_into().expect("Error length"))
                .expect("Deserialize pubkey failed")
        };

        let num_chunks = new_transcript.num_g1_powers as usize / G1_LENGTH;
        assert_eq!(proof.0.len(), num_chunks);
        assert_eq!(new_transcript.num_g1_powers as usize % G1_LENGTH, 0);

        for (i, (proof_g1, (old_g1_transcript, new_g1_transcript))) in proof
            .0
            .iter()
            .zip(
                old_transcript
                    .powers_of_tau
                    .g1_powers
                    .chunks(G1_LENGTH)
                    .zip(new_transcript.powers_of_tau.g1_powers.chunks(G1_LENGTH)),
            )
            .enumerate()
        {
            let old_points = decode_g1_points(old_g1_transcript);
            let new_points = decode_g1_points(new_g1_transcript);

            let instances = circuit_g1_mul::generate_instance(&G1_Instance {
                from_index: i * G1_LENGTH,
                pubkey,
                old_points,
                new_points,
            });

            g1_verify_proof(&g1_params, &g1_vk, &proof_g1, &instances);
        }

        let num_chunks = new_transcript.num_g2_powers as usize / G2_LENGTH;
        assert_eq!(proof.1.len(), num_chunks);
        assert_eq!(new_transcript.num_g2_powers as usize % G2_LENGTH, 1);

        assert_eq!(
            old_transcript.powers_of_tau.g2_powers[0],
            new_transcript.powers_of_tau.g2_powers[0]
        );
        for (i, (proof_g2, (old_g2_transcript, new_g2_transcript))) in proof
            .1
            .iter()
            .zip(
                old_transcript.powers_of_tau.g2_powers[1..]
                    .chunks(G2_LENGTH)
                    .zip(new_transcript.powers_of_tau.g2_powers[1..].chunks(G2_LENGTH)),
            )
            .enumerate()
        {
            let old_points = decode_g2_points(old_g2_transcript);
            let new_points = decode_g2_points(new_g2_transcript);

            let instances = circuit_g2_mul::generate_instance(&G2_Instance {
                from_index: i * G2_LENGTH + 1,
                pubkey,
                old_points,
                new_points,
            });

            g2_verify_proof(&g2_params, &g2_vk, &proof_g2, &instances).is_ok();
        }
    }
}

fn decode_g1_points(points: &[String]) -> Vec<bls12_381::G1Affine> {
    points
        .iter()
        .map(|p| {
            let bytes = hex::decode(&p[2..]).expect("Failed to decode point in hex string");

            bls12_381::G1Affine::from_compressed(&bytes.try_into().expect("Error length"))
                .expect("Deserialize G1 failed")
        })
        .collect::<Vec<_>>()
}

fn decode_g2_points(points: &[String]) -> Vec<bls12_381::G2Affine> {
    points
        .iter()
        .map(|p| {
            let bytes = hex::decode(&p[2..]).expect("Failed to decode point in hex string");

            bls12_381::G2Affine::from_compressed(&bytes.try_into().expect("Error length"))
                .expect("Deserialize G1 failed")
        })
        .collect::<Vec<_>>()
}

#[tokio::main]
async fn pull_transcripts() -> BatchTranscript {
    println!("Pulling transcripts...");

    let transcripts =
        match reqwest::get("https://seq.ceremony.ethereum.org/info/current_state").await {
            Ok(resp) => resp.json().await.unwrap(),
            Err(err) => panic!("Error: {}", err),
        };

    transcripts
}

fn scalar_from_string(tau: &String) -> bls12_381::Fr {
    let hex_str = if tau.starts_with("0x") {
        &tau[2..]
    } else {
        tau
    };

    let hex_str = if hex_str.len() % 2 == 0 {
        hex_str.to_string()
    } else {
        format!("0{}", hex_str)
    };

    let mut bytes = hex::decode(hex_str).expect("Failed to decode tau in hex string");
    // convert to little endian
    bytes.reverse();
    bytes.resize(32, 0);

    bls12_381::Fr::from_bytes(&bytes.try_into().expect("Error length")).expect("Invalid tau")
}
