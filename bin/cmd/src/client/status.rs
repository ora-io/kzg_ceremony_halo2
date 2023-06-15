use crate::client::request::Client;
use crate::client::SEQUENCER;

#[tokio::main]
pub async fn status() {
    let client = Client::new(SEQUENCER.to_string());

    let status = client.get_current_status().await;
    match status {
        Ok(s) => {
            println!("{}", s);
        }
        Err(e) => {
            println!("{}", e);
        }
    }
}
