use kzg_ceremony_circuit::K;
use kzg_ceremony_prover::serialization::{BatchContribution, BatchContributionJson, Decode};
use kzg_ceremony_prover::verify_proofs;
use std::fs;

#[tokio::main]
pub async fn verify_halo2_proofs() {
    println!("Load old contributions:");
    let old_contributions =
        fs::read_to_string("old_contributions.json").expect("Read old contributions failed.");
    let old_contributions: BatchContributionJson =
        serde_json::from_str(&old_contributions).expect("Deserialize old contributions failed.");
    let old_contributions = old_contributions.decode();

    println!("Load new contributions:");
    let new_contributions =
        fs::read_to_string("new_contributions.json").expect("Read new contributions failed.");
    let new_contributions: BatchContributionJson =
        serde_json::from_str(&new_contributions).expect("Deserialize new contributions failed.");
    let new_contributions = new_contributions.decode();

    println!("Load proofs:");
    let proofs = fs::read_to_string("Proof.json").expect("Read proofs failed.");

    println!("Load params:");
    let params = fs::read(format!("./lib/kzg_ceremony_circuit/params_{}.bin", K))
        .expect("Read params file failed");

    verify_proofs(&old_contributions, &new_contributions, proofs, params);
}
