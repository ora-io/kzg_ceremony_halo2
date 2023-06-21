use blake2::Digest;
use rand::rngs::OsRng;
use std::fs;
use std::io::Write;
use std::ops::{Mul, MulAssign};

use kzg_ceremony_circuit::halo2_proofs::arithmetic::Field;
use kzg_ceremony_prover::prove;
use kzg_ceremony_prover::serialization::BatchContributionJson;

use crate::bls12_381::{Fr, G2Affine};
use crate::client::request::{Client, Status};
use crate::client::{MIN_RANDOMNESS_LEN, SEQUENCER};
use crate::serialization::{BatchContribution, Contribution, Decode, Encode, PowersOfTau};
use crate::Curve;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct BatchContributionWithProof {
    contributions: BatchContributionJson,
    proofs: String,
}

#[tokio::main]
pub async fn contribute_ceremony(session_id: String, randomness: String) {
    if randomness.len() < MIN_RANDOMNESS_LEN {
        println!("randomness must be >= 64 bytes");
        return;
    }
    let client = Client::new(SEQUENCER.to_string());

    match client.get_current_status().await {
        Ok(s) => {
            println!("{}", s);
        }
        Err(e) => {
            println!("{}", e);
            return;
        }
    }

    // Get previous contribution
    let prev_batch_contribution_json;
    loop {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        println!("{} sending try_contribute", now);

        let bc = client.post_try_contribute(&session_id).await;

        match bc {
            Ok(bc) => {
                if bc.1 == Status::StatusReauth {
                    println!("SessionID has expired, authenticate again");
                    return;
                }
                if bc.1 == Status::StatusProceed {
                    prev_batch_contribution_json = bc.0.unwrap();
                    break;
                }
            }
            Err(e) => {
                println!("{}", e);
            }
        }

        match client.get_current_status().await {
            Ok(s) => {
                println!("{}", s);
            }
            Err(e) => {
                println!("{}", e);
                return;
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(30));
    }

    println!("Storing Previous contribution.");
    let old_contributions_json = serde_json::to_string(&prev_batch_contribution_json)
        .expect("Serialize prev_batch_contribution failed");
    let mut file = fs::File::create("old_contributions.json").expect("Create file failed");
    file.write_all(old_contributions_json.as_bytes())
        .expect("Write prev_batch_contribution failed");

    let now = std::time::Instant::now();
    let prev_batch_contribution = prev_batch_contribution_json.decode();
    let duration = now.elapsed();
    println!("Deserialization took {}s", duration.as_secs());

    println!("Starting to compute new contribution.");
    let start = std::time::Instant::now();
    let taus = tau(randomness, prev_batch_contribution.contributions.len());
    let new_batch_contribution = contribute(&prev_batch_contribution, &taus);
    let duration = start.elapsed();
    println!("Contribution ready, took {}s", duration.as_secs());

    println!("Storing new contribution .");
    let now = std::time::Instant::now();
    let new_batch_contribution_json = new_batch_contribution.encode();
    let new_contributions_json = serde_json::to_string(&new_batch_contribution_json)
        .expect("Serialize new_batch_contribution failed");
    let mut file = fs::File::create("new_contributions.json").expect("Create file failed");
    file.write_all(new_contributions_json.as_bytes())
        .expect("Write new_batch_contribution failed");
    let duration = now.elapsed();
    println!("Serialization and storing took {}s", duration.as_secs());

    // Prove
    let proofs = prove(&prev_batch_contribution, &new_batch_contribution, &taus);
    let serialized_proof = serde_json::to_string(&proofs).expect("Serialize proof failed");
    let mut file = fs::File::create("Proof.json").expect("Create file failed");
    file.write_all(serialized_proof.as_bytes())
        .expect("Write proof failed");

    //verify
    let g1_params = std::fs::read("../../lib/kzg_ceremony_circuit/g1_params.bin")
        .expect("Read G2 params file failed");
    let g2_params = std::fs::read("../../lib/kzg_ceremony_circuit/g2_params.bin")
        .expect("Read G2 params file failed");
    kzg_ceremony_prover::verify_proofs(
        &prev_batch_contribution,
        &new_batch_contribution,
        serialized_proof.clone(),
        g1_params,
        g2_params,
    );

    println!("Sending contribution.");
    let bc_with_proofs = BatchContributionWithProof {
        contributions: new_batch_contribution_json,
        proofs: serialized_proof,
    };
    let bc_with_proofs = serde_json::to_string(&bc_with_proofs).expect("Serialize failed");
    let receipt = client.post_contribute(&session_id, &bc_with_proofs).await;
    match receipt {
        Ok(r) => {
            println!("Contribute OK.");
            println!("{}", r);
            let serialized = serde_json::to_string(&r).expect("Serialize receipt failed");
            let mut file = std::fs::File::create("receipt.json").expect("Create file failed");
            file.write_all(serialized.as_bytes())
                .expect("Write receipt failed");
        }
        Err(_) => {
            println!("Send contribution failed.");
        }
    }
}

pub(crate) fn contribute(pre_bc: &BatchContribution, taus: &Vec<Fr>) -> BatchContribution {
    let mut contributions = vec![];
    for (contribution, tau) in pre_bc.contributions.iter().zip(taus.iter()) {
        let powers_of_tau: Vec<_> = std::iter::repeat(tau)
            .scan(Fr::one(), |state, el| {
                let old_state = *state;
                state.mul_assign(el);
                Some(old_state)
            })
            .take(contribution.num_g1_powers as usize)
            .collect();

        let g1_powers = contribution
            .powers_of_tau
            .g1_powers
            .iter()
            .zip(powers_of_tau.iter())
            .map(|(old_state, tau)| old_state.mul(tau).to_affine())
            .collect::<Vec<_>>();

        let g2_powers = contribution
            .powers_of_tau
            .g2_powers
            .iter()
            .zip(powers_of_tau.iter())
            .map(|(old_state, tau)| old_state.mul(tau).to_affine())
            .collect::<Vec<_>>();

        let pot_pubkey = G2Affine::generator().mul(tau).to_affine();
        contributions.push(Contribution {
            num_g1_powers: contribution.num_g1_powers,
            num_g2_powers: contribution.num_g2_powers,
            powers_of_tau: PowersOfTau {
                g1_powers,
                g2_powers,
            },
            pot_pubkey,
        })
    }

    BatchContribution { contributions }
}

fn tau(randomness: String, num: usize) -> Vec<Fr> {
    let randomness = randomness.into_bytes();

    let mut taus = vec![];
    for i in 0..num {
        let fr = {
            let mut seed = randomness.clone();
            seed.push(i as u8);

            let mut hasher = blake2::Blake2b512::new();
            hasher.update(&seed);
            let result = hasher.finalize();

            Fr::from_bytes_wide(&result.into())
        };

        let random_fr = Fr::random(OsRng);
        taus.push(fr * random_fr);
    }

    taus
}

#[cfg(test)]
mod tests {
    use crate::client::contribute::contribute;
    use crate::client::request::Client;
    use crate::client::SEQUENCER;
    use crate::serialization::{BatchContribution, Contribution, Encode, PowersOfTau};
    use kzg_ceremony_circuit::halo2_proofs::arithmetic::Field;
    use kzg_ceremony_circuit::halo2_proofs::pairing::bls12_381::Fr;
    use kzg_ceremony_prover::{prove, verify_proofs};
    use rand::rngs::OsRng;
    use std::io::Write;
    use std::time::Instant;

    #[tokio::test]
    async fn pull_and_test() {
        let client = Client::new(SEQUENCER.to_string());
        println!("Pull previous transcripts");
        let cur_state = client.get_current_state().await.unwrap();
        println!("End");
        let old_contributions = cur_state
            .transcripts
            .iter()
            .map(|t| Contribution {
                num_g1_powers: t.num_g1_powers,
                num_g2_powers: t.num_g2_powers,
                powers_of_tau: PowersOfTau {
                    g1_powers: t.powers_of_tau.g1_powers.clone(),
                    g2_powers: t.powers_of_tau.g2_powers.clone(),
                },
                pot_pubkey: Default::default(),
            })
            .collect::<Vec<_>>();
        let old_contributions = BatchContribution {
            contributions: old_contributions,
        };

        println!("Storing old contribution.");
        let serialized_old = serde_json::to_string(&old_contributions.encode())
            .expect("Serialize prev_batch_contribution failed");
        let mut file = std::fs::File::create("old_contributions.json").expect("Create file failed");
        file.write_all(serialized_old.as_bytes())
            .expect("Write prev_batch_contribution failed");

        let taus = std::iter::repeat(Fr::random(OsRng))
            .take(old_contributions.contributions.len())
            .collect::<Vec<_>>();

        let new_contributions = contribute(&old_contributions, &taus);

        println!("Storing new contribution.");
        let serialized_new = serde_json::to_string(&new_contributions.encode())
            .expect("Serialize new_contributions failed");
        let mut file = std::fs::File::create("new_contributions.json").expect("Create file failed");
        file.write_all(serialized_new.as_bytes())
            .expect("Write new_contributions failed");

        let now = Instant::now();
        let proofs = prove(&old_contributions, &new_contributions, &taus);
        let duration = now.elapsed();
        let serialized_proof = serde_json::to_string(&proofs).expect("Serialize proof failed");
        println!("Prover took {}s", duration.as_secs());

        println!("Verifying");
        let g1_params = std::fs::read("../../lib/kzg_ceremony_circuit/g1_params.bin")
            .expect("Read G2 params file failed");
        let g2_params = std::fs::read("../../lib/kzg_ceremony_circuit/g2_params.bin")
            .expect("Read G2 params file failed");
        let now = Instant::now();
        verify_proofs(
            &old_contributions,
            &new_contributions,
            serialized_proof,
            g1_params,
            g2_params,
        );
        let duration = now.elapsed();
        println!("Verifier took {}s", duration.as_secs());
    }
}
