use kzg_ceremony_circuit::halo2_proofs::pairing::bls12_381::Fr;
use kzg_ceremony_circuit::K;
use kzg_ceremony_prover::prove;
use kzg_ceremony_prover::serialization::{BatchContributionJson, Decode};
use std::io::Write;
use std::{fs, io};

pub fn offline_prove() {
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

    println!("Load params:");
    let params = fs::read(format!("./lib/kzg_ceremony_circuit/params_{}.bin", K))
        .expect("Read params file failed");

    let mut taus = vec![];
    println!("Please input taus");
    while taus.len() < old_contributions.contributions.len() {
        let mut t = String::new();
        io::stdin().read_line(&mut t).unwrap();
        let t = t.trim();
        let t = t.strip_prefix("0x").unwrap_or(&t);
        let mut bytes = hex::decode(t).unwrap();
        bytes.reverse();

        taus.push(Fr::from_bytes(&bytes.try_into().unwrap()).unwrap());
    }

    let proofs = prove(&old_contributions, &new_contributions, &taus, &params);
    let serialized_proof = serde_json::to_string(&proofs).expect("Serialize proof failed");
    let mut file = fs::File::create("Proof.json").expect("Create file failed");
    file.write_all(serialized_proof.as_bytes())
        .expect("Write proof failed");
    println!("Done.");
}
