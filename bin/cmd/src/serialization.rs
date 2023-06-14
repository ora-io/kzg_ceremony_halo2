use kzg_ceremony_circuit::halo2_proofs::pairing::group::prime::PrimeCurveAffine;
use kzg_ceremony_circuit::halo2_proofs::pairing::group::Curve;
use serde::{Deserialize, Serialize};

use crate::bls12_381::{Fr, G1Affine, G2Affine};

// TODO: multi-threads
macro_rules! encode_points {
    ($t:ty, $points:expr) => {
        $points
            .iter()
            .map(|p: &$t| format!("0x{}", hex::encode(p.to_compressed())))
            .collect::<Vec<String>>()
    };
}

macro_rules! decode_points {
    ($t:ty, $points:expr) => {
        $points
            .iter()
            .map(|p: &String| {
                let bytes = hex::decode(&p[2..]).expect("Failed to decode point in hex string");
                <$t>::from_compressed(&bytes.try_into().expect("Error length"))
                    .expect("Deserialize failed")
            })
            .collect::<Vec<_>>()
    };
}

pub trait Encode {
    type Output;

    fn encode(&self) -> Self::Output;
}

pub trait Decode {
    type Output;

    fn decode(&self) -> Self::Output;
}

pub struct PowersOfTau {
    pub g1_powers: Vec<G1Affine>,
    pub g2_powers: Vec<G2Affine>,
}

impl Encode for PowersOfTau {
    type Output = PowersOfTauJson;

    fn encode(&self) -> Self::Output {
        PowersOfTauJson {
            g1_powers: encode_points!(G1Affine, self.g1_powers),
            g2_powers: encode_points!(G2Affine, self.g2_powers),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PowersOfTauJson {
    #[serde(rename = "G1Powers")]
    pub g1_powers: Vec<String>,
    #[serde(rename = "G2Powers")]
    pub g2_powers: Vec<String>,
}

impl Decode for PowersOfTauJson {
    type Output = PowersOfTau;

    fn decode(&self) -> Self::Output {
        PowersOfTau {
            g1_powers: decode_points!(G1Affine, self.g1_powers),
            g2_powers: decode_points!(G2Affine, self.g2_powers),
        }
    }
}

pub struct Witness {
    pub running_products: Vec<G1Affine>,
    pub pot_pubkeys: Vec<G2Affine>,
    pub bls_signatures: Vec<Option<G1Affine>>,
}

impl Encode for Witness {
    type Output = WitnessJson;

    fn encode(&self) -> Self::Output {
        let bls_signatures = self
            .bls_signatures
            .iter()
            .map(|s| match s {
                None => "".to_string(),
                Some(p) => {
                    format!("0x{}", hex::encode(p.to_compressed()))
                }
            })
            .collect();

        WitnessJson {
            running_products: encode_points!(G1Affine, self.running_products),
            pot_pubkeys: encode_points!(G2Affine, self.pot_pubkeys),
            bls_signatures,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WitnessJson {
    #[serde(rename = "runningProducts")]
    pub running_products: Vec<String>,
    #[serde(rename = "potPubkeys")]
    pub pot_pubkeys: Vec<String>,
    #[serde(rename = "blsSignatures")]
    pub bls_signatures: Vec<String>,
}

impl Decode for WitnessJson {
    type Output = Witness;

    fn decode(&self) -> Self::Output {
        let bls_signatures = self
            .bls_signatures
            .iter()
            .map(|s| {
                if s.is_empty() {
                    None
                } else {
                    let bytes = hex::decode(&s[2..]).expect("Failed to decode point in hex string");
                    let p = G1Affine::from_compressed(&bytes.try_into().expect("Error length"))
                        .expect("Deserialize G1 failed");

                    Some(p)
                }
            })
            .collect();

        Witness {
            running_products: decode_points!(G1Affine, self.running_products),
            pot_pubkeys: decode_points!(G2Affine, self.pot_pubkeys),
            bls_signatures,
        }
    }
}

pub struct Transcript {
    pub num_g1_powers: u32,
    pub num_g2_powers: u32,
    pub powers_of_tau: PowersOfTau,
    pub witness: Witness,
}

impl Encode for Transcript {
    type Output = TranscriptJson;

    fn encode(&self) -> Self::Output {
        TranscriptJson {
            num_g1_powers: self.num_g1_powers,
            num_g2_powers: self.num_g2_powers,
            powers_of_tau: self.powers_of_tau.encode(),
            witness: self.witness.encode(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TranscriptJson {
    #[serde(rename = "numG1Powers")]
    pub num_g1_powers: u32,
    #[serde(rename = "numG2Powers")]
    pub num_g2_powers: u32,
    #[serde(rename = "powersOfTau")]
    pub powers_of_tau: PowersOfTauJson,
    pub witness: WitnessJson,
}

impl Decode for TranscriptJson {
    type Output = Transcript;

    fn decode(&self) -> Self::Output {
        Transcript {
            num_g1_powers: self.num_g1_powers,
            num_g2_powers: self.num_g2_powers,
            powers_of_tau: self.powers_of_tau.decode(),
            witness: self.witness.decode(),
        }
    }
}

pub struct BatchTranscript {
    pub transcripts: Vec<Transcript>,
    pub participant_ids: Vec<String>,
    pub participant_ecdsa_signatures: Vec<String>,
}

impl Encode for BatchTranscript {
    type Output = BatchTranscriptJson;

    fn encode(&self) -> Self::Output {
        BatchTranscriptJson {
            transcripts: self.transcripts.iter().map(|t| t.encode()).collect(),
            participant_ids: self.participant_ids.clone(),
            participant_ecdsa_signatures: self.participant_ecdsa_signatures.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchTranscriptJson {
    pub transcripts: Vec<TranscriptJson>,
    #[serde(rename = "participantIds")]
    pub participant_ids: Vec<String>,
    #[serde(rename = "participantEcdsaSignatures")]
    pub participant_ecdsa_signatures: Vec<String>,
}

impl Decode for BatchTranscriptJson {
    type Output = BatchTranscript;

    fn decode(&self) -> Self::Output {
        BatchTranscript {
            transcripts: self.transcripts.iter().map(|t| t.decode()).collect(),
            participant_ids: self.participant_ids.clone(),
            participant_ecdsa_signatures: self.participant_ecdsa_signatures.clone(),
        }
    }
}

pub struct Contribution {
    pub num_g1_powers: u32,
    pub num_g2_powers: u32,
    pub powers_of_tau: PowersOfTau,
    pub pot_pubkey: G2Affine,
}

impl Encode for Contribution {
    type Output = ContributionJson;

    fn encode(&self) -> Self::Output {
        let mut pot_pubkeys = encode_points!(G2Affine, vec![self.pot_pubkey]);

        ContributionJson {
            num_g1_powers: self.num_g1_powers,
            num_g2_powers: self.num_g2_powers,
            powers_of_tau: self.powers_of_tau.encode(),
            pot_pubkey: pot_pubkeys.pop().unwrap(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContributionJson {
    #[serde(rename = "numG1Powers")]
    pub num_g1_powers: u32,
    #[serde(rename = "numG2Powers")]
    pub num_g2_powers: u32,
    #[serde(rename = "powersOfTau")]
    pub powers_of_tau: PowersOfTauJson,
    #[serde(rename = "potPubkey")]
    pub pot_pubkey: String,
}

impl Decode for ContributionJson {
    type Output = Contribution;

    fn decode(&self) -> Self::Output {
        let mut pot_pubkey = decode_points!(G2Affine, vec![self.pot_pubkey.clone()]);

        Contribution {
            num_g1_powers: self.num_g1_powers,
            num_g2_powers: self.num_g2_powers,
            powers_of_tau: self.powers_of_tau.decode(),
            pot_pubkey: pot_pubkey.pop().unwrap(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchContributionJson {
    contributions: Vec<ContributionJson>,
}

impl Decode for BatchContributionJson {
    type Output = BatchContribution;

    fn decode(&self) -> Self::Output {
        BatchContribution {
            contributions: self.contributions.iter().map(|c| c.decode()).collect(),
        }
    }
}

pub struct BatchContribution {
    pub(crate) contributions: Vec<Contribution>,
}

impl Encode for BatchContribution {
    type Output = BatchContributionJson;

    fn encode(&self) -> Self::Output {
        BatchContributionJson {
            contributions: self.contributions.iter().map(|c| c.encode()).collect(),
        }
    }
}

pub fn scalar_from_string(tau: &String) -> Fr {
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

    Fr::from_bytes(&bytes.try_into().expect("Error length")).expect("Invalid tau")
}

#[test]
fn test_deserialize() {
    use std::fs;
    let test_string = fs::read_to_string("test.json").expect("should exist");
    let batch_transcript: BatchTranscriptJson =
        serde_json::from_str(&test_string).expect("Deserialize failed");
    println!("batch transcript {:?}", batch_transcript);
}

#[test]
fn test_encode() {
    let p = G1Affine::generator() * Fr::from(10u64);
    let p = p.to_affine();

    let bytes = p.to_compressed();
    let h = format!("0x{}", hex::encode(bytes));
    println!("{}", h);
}
