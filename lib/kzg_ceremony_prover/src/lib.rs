use crate::serialization::{BatchContribution, Proof};
use ark_std::{end_timer, start_timer};
use kzg_ceremony_circuit::circuit_g1_mul::{
    verify_proof as g1_verify_proof, Circuit as G1_Circuit, Instance as G1_Instance,
    ProvingKey as G1_PK, VerifyingKey as G1_VK, LENGTH as G1_LENGTH,
};
use kzg_ceremony_circuit::circuit_g2_mul::{
    verify_proof as g2_verify_proof, Circuit as G2_Circuit, Instance as G2_Instance,
    ProvingKey as G2_PK, VerifyingKey as G2_VK, LENGTH as G2_LENGTH,
};
use kzg_ceremony_circuit::halo2_proofs::pairing::bls12_381::Fr as Scalar;
use kzg_ceremony_circuit::halo2_proofs::pairing::bn256::Fr;
use kzg_ceremony_circuit::halo2_proofs::pairing::group::Curve;
use kzg_ceremony_circuit::halo2_proofs::pairing::{bls12_381, bn256};
use kzg_ceremony_circuit::halo2_proofs::poly::commitment::Params;
use kzg_ceremony_circuit::{circuit_g1_mul, circuit_g2_mul};
use rayon::prelude::*;

pub mod serialization;

pub fn prove(
    old_contributions: &BatchContribution,
    new_contributions: &BatchContribution,
    taus: &Vec<Scalar>,
    params: &Vec<u8>,
) -> Proof {
    println!("Proving");

    let params = Params::<bn256::G1Affine>::read(&params[..]).expect("Read params failed");

    println!("Building G1 Proving Key..");
    let g1_pk = G1_PK::build(&params);

    println!("Building G2 Proving Key..");
    let g2_pk = G2_PK::build(&params);

    println!("Generating proofs...");
    let mut proofs = vec![];
    for (i, (tau, (old_contribution, new_contribution))) in taus
        .iter()
        .zip(
            old_contributions
                .contributions
                .iter()
                .zip(new_contributions.contributions.iter()),
        )
        .enumerate()
    {
        println!("Processing contributions {}...", i);

        let pubkey = (bls12_381::G2Affine::generator() * tau).to_affine();

        println!("Processing G1 proofs...");
        let number_g1_powers = old_contribution.num_g1_powers as usize;
        assert_eq!(number_g1_powers % G1_LENGTH, 0);
        let number_g1_proofs = number_g1_powers / G1_LENGTH;

        let mut proofs_g1 = Vec::with_capacity(number_g1_proofs);
        for (j, (old_points, new_points)) in old_contribution
            .powers_of_tau
            .g1_powers
            .chunks(G1_LENGTH)
            .zip(new_contribution.powers_of_tau.g1_powers.chunks(G1_LENGTH))
            .enumerate()
        {
            println!("Generating G1 proof {}.{}...", i, j);
            let from_index = j * G1_LENGTH;

            let g1_circuit = G1_Circuit::<Fr> {
                from_index: Some(from_index),
                tau: Some(*tau),
                pubkey: Some(pubkey),
                points: old_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
                new_points: new_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
                _mark: Default::default(),
            };

            let instances = circuit_g1_mul::generate_instance(&G1_Instance {
                from_index,
                pubkey,
                old_points: old_points.to_vec(),
                new_points: new_points.to_vec(),
            });
            let proof_g1 = circuit_g1_mul::create_proofs(&params, g1_circuit, &g1_pk, &instances);
            proofs_g1.push(proof_g1);
        }

        println!("Processing G2 proofs...");
        let number_g2_powers = old_contribution.num_g2_powers as usize;
        assert_eq!(number_g2_powers % G2_LENGTH, 1);
        let number_g2_proofs = number_g2_powers / G2_LENGTH;

        let mut proofs_g2 = Vec::with_capacity(number_g2_proofs);
        for (j, (old_points, new_points)) in old_contribution.powers_of_tau.g2_powers[1..]
            .chunks(G2_LENGTH)
            .zip(new_contribution.powers_of_tau.g2_powers[1..].chunks(G2_LENGTH))
            .enumerate()
        {
            println!("Generating G2 proof {},{}", i, j);
            let from_index = j * G2_LENGTH + 1;

            let g2_circuit = G2_Circuit::<Fr> {
                from_index: Some(from_index),
                tau: Some(*tau),
                pubkey: Some(pubkey),
                points: old_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
                new_points: new_points.iter().map(|p| Some(*p)).collect::<Vec<_>>(),
                _mark: Default::default(),
            };

            let instances = circuit_g2_mul::generate_instance(&G2_Instance {
                from_index,
                pubkey,
                old_points: old_points.to_vec(),
                new_points: new_points.to_vec(),
            });
            let proof_g2 = circuit_g2_mul::create_proofs(&params, g2_circuit, &g2_pk, &instances);
            proofs_g2.push(proof_g2);
        }

        proofs.push((proofs_g1, proofs_g2));
    }

    Proof(proofs)
}

pub fn verify_proofs(
    old_contributions: &BatchContribution,
    new_contributions: &BatchContribution,
    proofs: String,
    params: Vec<u8>,
) {
    println!("Verifying");

    let proofs: Proof = serde_json::from_str(&proofs).expect("Deserialize proof failed");

    println!("Reading params...");
    let params = Params::<bn256::G1Affine>::read(&params[..]).expect("Read params failed");

    println!("Building G1 Verification Key..");
    let g1_vk = G1_VK::build(&params);

    println!("Building G2 Verification Key..");
    let g2_vk = G2_VK::build(&params);

    assert_eq!(proofs.0.len(), new_contributions.contributions.len());
    let timer = start_timer!(|| "Verify proofs");
    for (proof, (old_contribution, new_contribution)) in proofs.0.iter().zip(
        old_contributions
            .contributions
            .iter()
            .zip(new_contributions.contributions.iter()),
    ) {
        let pubkey = new_contribution.pot_pubkey;

        let num_chunks = new_contribution.num_g1_powers as usize / G1_LENGTH;
        assert_eq!(proof.0.len(), num_chunks);
        assert_eq!(new_contribution.num_g1_powers as usize % G1_LENGTH, 0);

        let data = proof
            .0
            .iter()
            .zip(
                old_contribution
                    .powers_of_tau
                    .g1_powers
                    .chunks(G1_LENGTH)
                    .zip(new_contribution.powers_of_tau.g1_powers.chunks(G1_LENGTH)),
            )
            .collect::<Vec<_>>();

        data.par_iter()
            .enumerate()
            .for_each(|(i, &(proof_g1, (old_points, new_points)))| {
                let instances = circuit_g1_mul::generate_instance(&G1_Instance {
                    from_index: i * G1_LENGTH,
                    pubkey,
                    old_points: old_points.to_vec(),
                    new_points: new_points.to_vec(),
                });

                g1_verify_proof(&params, &g1_vk, &proof_g1, &instances).unwrap();
            });

        let num_chunks = new_contribution.num_g2_powers as usize / G2_LENGTH;
        assert_eq!(proof.1.len(), num_chunks);
        assert_eq!(new_contribution.num_g2_powers as usize % G2_LENGTH, 1);

        assert_eq!(
            old_contribution.powers_of_tau.g2_powers[0],
            new_contribution.powers_of_tau.g2_powers[0]
        );

        let data = proof
            .1
            .iter()
            .zip(
                old_contribution.powers_of_tau.g2_powers[1..]
                    .chunks(G2_LENGTH)
                    .zip(new_contribution.powers_of_tau.g2_powers[1..].chunks(G2_LENGTH)),
            )
            .collect::<Vec<_>>();

        data.par_iter()
            .enumerate()
            .for_each(|(i, &(proof_g2, (old_points, new_points)))| {
                let instances = circuit_g2_mul::generate_instance(&G2_Instance {
                    from_index: i * G2_LENGTH + 1,
                    pubkey,
                    old_points: old_points.to_vec(),
                    new_points: new_points.to_vec(),
                });

                g2_verify_proof(&params, &g2_vk, &proof_g2, &instances).unwrap();
            });
    }
    end_timer!(timer);
}
