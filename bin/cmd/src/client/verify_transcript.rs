use crate::client::request::Client;
use crate::client::SEQUENCER;

use crate::bls12_381::{pairing, G1Affine, G2Affine};
use rayon::prelude::{IntoParallelIterator, ParallelIterator};

#[tokio::main]
pub async fn verify_transcript() {
    let client = Client::new(SEQUENCER.to_string());

    println!("Pulling current transcript from sequencer...");
    let status = client.get_current_state().await;
    if let Err(e) = status {
        println!("{}", e);
        return;
    }
    println!("OK");

    let mut status = status.unwrap();

    println!("Verifying transcript...");
    let start = std::time::Instant::now();
    let g2_generator = G2Affine::generator();
    let g1_generator = G1Affine::generator();
    let mut i = 0usize;
    for transcript in status.transcripts.iter_mut() {
        println!("transcript {}", {
            i += 1;
            i
        });
        // `tau_update_check`
        let l = transcript.witness.running_products.len() - 1;
        let checks = (0..l - 1)
            .into_par_iter()
            .map(|j| {
                let cur_running_product = transcript.witness.running_products[j];
                let next_running_product = transcript.witness.running_products[j + 1];
                let pot_pubkey = transcript.witness.pot_pubkeys[j + 1];

                pairing(&cur_running_product, &pot_pubkey)
                    == pairing(&next_running_product, &g2_generator)
            })
            .collect::<Vec<_>>();
        if checks.iter().any(|&check| !check) {
            panic!("paring check failed");
        }

        // Check that the last running product is equal to G1 first power.
        let last_running_product = transcript.witness.running_products[l];
        assert_eq!(
            last_running_product, transcript.powers_of_tau.g1_powers[1],
            "last running product doesn't match tau first power"
        );

        // Check that the first running product is the tau^0 power.
        let first_running_product = transcript.witness.running_products[0];
        assert_eq!(
            first_running_product, transcript.powers_of_tau.g1_powers[0],
            "the first running product element should match"
        );

        // `g1PowersCheck`: checks that the G1 powers in the transcript are coherent powers.
        let l = transcript.powers_of_tau.g1_powers.len();
        let base_tau_g2 = transcript.powers_of_tau.g2_powers[1];
        let checks = (0..l - 1)
            .into_par_iter()
            .map(|j| {
                let cur_g1 = transcript.powers_of_tau.g1_powers[j];
                let next_g1 = transcript.powers_of_tau.g1_powers[j + 1];

                pairing(&cur_g1, &base_tau_g2) == pairing(&next_g1, &g2_generator)
            })
            .collect::<Vec<_>>();
        if checks.iter().any(|&check| !check) {
            panic!("paring check failed");
        }

        // `g2PowersCheck`: checks that the G2 powers in the transcript are coherent powers.
        let l = transcript.powers_of_tau.g2_powers.len();
        let base_tau_g1 = transcript.powers_of_tau.g1_powers[1];
        let checks = (0..l - 1)
            .into_par_iter()
            .map(|j| {
                let cur_g2 = transcript.powers_of_tau.g2_powers[j];
                let next_g2 = transcript.powers_of_tau.g2_powers[j + 1];

                pairing(&base_tau_g1, &cur_g2) == pairing(&g1_generator, &next_g2)
            })
            .collect::<Vec<_>>();
        if checks.iter().any(|&check| !check) {
            panic!("paring check failed");
        }
    }
    let duration = start.elapsed();
    println!("Verifier takes {}s", duration.as_secs());
}
