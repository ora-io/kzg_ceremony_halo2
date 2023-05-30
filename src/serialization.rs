use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowersOfTau {
    #[serde(rename = "G1Powers")]
    pub g1_powers: Vec<String>,
    #[serde(rename = "G2Powers")]
    pub g2_powers: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Witness {
    #[serde(rename = "runningProducts")]
    pub running_products: Vec<String>,
    #[serde(rename = "potPubkeys")]
    pub pot_pubkeys: Vec<String>,
    #[serde(rename = "blsSignatures")]
    pub bls_signatures: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transcript {
    #[serde(rename = "numG1Powers")]
    pub num_g1_powers: u32,
    #[serde(rename = "numG2Powers")]
    pub num_g2_powers: u32,
    #[serde(rename = "powersOfTau")]
    pub powers_of_tau: PowersOfTau,
    pub witness: Witness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchTranscript {
    pub transcripts: Vec<Transcript>,
    #[serde(rename = "participantIds")]
    pub participant_ids: Vec<String>,
    #[serde(rename = "participantEcdsaSignatures")]
    pub participant_ecdsa_signatures: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contribution {
    #[serde(rename = "numG1Powers")]
    pub num_g1_powers: u32,
    #[serde(rename = "numG2Powers")]
    pub num_g2_powers: u32,
    #[serde(rename = "powersOfTau")]
    pub powers_of_tau: PowersOfTau,
    #[serde(rename = "potPubkey")]
    pub pot_pubkey: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchContribution {
    contributions: Vec<Contribution>,
}

#[test]
fn test_deserialize() {
    use std::fs;
    let test_string = fs::read_to_string("test.json").expect("should exist");
    let batch_transcript: BatchTranscript =
        serde_json::from_str(&test_string).expect("Deserialize failed");
    println!("batch transcript {:?}", batch_transcript);
}
