use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ErrorMsg {
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct MsgStatus {
    pub lobby_size: u64,
    pub num_contributions: u64,
    pub sequencer_address: String,
}

impl MsgStatus {
    fn to_string(&self) -> String {
        format!(
            "Sequencer status:\n  Lobby size: {}\n  NumContributions: {}\n  SequencerAddress: {}\n",
            self.lobby_size, self.num_contributions, self.sequencer_address
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct IDToken {
    pub exp: u64,
    pub nickname: String,
    pub provider: String,
    pub sub: String,
}

#[derive(Serialize, Deserialize)]
pub struct MsgAuthCallback {
    pub id_token: IDToken,
    pub session_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct MsgContributeReceipt {
    pub receipt: String,
    pub signature: String,
}

impl MsgContributeReceipt {
    fn to_string(&self) -> String {
        format!(
            "Contribute Receipt:\n  Receipt: {}\n  Signature: {}\n",
            self.receipt, self.signature
        )
    }
}