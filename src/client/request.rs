extern crate reqwest;
extern crate serde;
extern crate serde_json;

use crate::client::message::{MsgContributeReceipt, MsgStatus};
use crate::serialization::BatchContribution;
use crate::BatchTranscript;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::StatusCode;
use std::error::Error;

struct Client {
    url: String,
    client: reqwest::Client,
}

#[derive(Debug)]
enum Status {
    StatusReauth,
    StatusProceed,
}

#[derive(Debug)]
struct CustomError {
    message: String,
}

impl CustomError {
    fn new(message: &str) -> Self {
        Self {
            message: message.to_string(),
        }
    }
}

impl std::fmt::Display for CustomError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Error {}", self.message)
    }
}

impl Error for CustomError {}

impl Client {
    fn new(sequencer_url: String) -> Client {
        Client {
            url: sequencer_url,
            client: reqwest::Client::new(),
        }
    }

    async fn post_with_auth(
        &self,
        url: &str,
        content_type: &str,
        body: &str,
        bearer: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(content_type).unwrap());
        headers.insert(AUTHORIZATION, HeaderValue::from_str(bearer).unwrap());

        self.client
            .post(url)
            .headers(headers)
            .body(body.to_string())
            .send()
            .await
    }

    async fn get_current_status(&self) -> Result<MsgStatus, Box<dyn Error>> {
        let resp = self
            .client
            .get(&format!("{}/info/status", self.url))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(Box::new(CustomError::new(&format!(
                "Unexpected http code: {}",
                resp.status()
            ))));
        }

        let msg: MsgStatus = resp.json().await?;
        Ok(msg)
    }

    async fn get_current_state(&self) -> Result<BatchTranscript, Box<dyn Error>> {
        let resp = self
            .client
            .get(&format!("{}/info/current_state", self.url))
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(Box::new(CustomError::new(&format!(
                "Unexpected http code: {}",
                resp.status()
            ))));
        }

        let state: BatchTranscript = resp.json().await?;
        Ok(state)
    }

    async fn post_try_contribute(
        &self,
        session_id: &str,
    ) -> Result<(Option<BatchContribution>, Status), Box<dyn Error>> {
        let bearer = format!("Bearer {}", session_id);
        let resp = self
            .post_with_auth(
                &format!("{}/lobby/try_contribute", self.url),
                "application/json",
                "",
                &bearer,
            )
            .await?;

        if !resp.status().is_success() {
            match resp.status() {
                StatusCode::BAD_REQUEST => {
                    return Err(Box::new(CustomError::new(
                        "call came to early. rate limited",
                    )));
                }
                StatusCode::UNAUTHORIZED => {
                    return Ok((None, Status::StatusReauth));
                }
                _ => {
                    return Err(Box::new(CustomError::new(&format!(
                        "Unexpected http code: {}",
                        resp.status()
                    ))));
                }
            }
        }

        let bc: BatchContribution = resp.json().await?;
        Ok((Some(bc), Status::StatusProceed))
    }

    async fn post_contribute(
        &self,
        session_id: &str,
        bc: &BatchContribution,
    ) -> Result<MsgContributeReceipt, Box<dyn Error>> {
        let bearer = format!("Bearer {}", session_id);
        let json_bc = serde_json::to_string(bc).unwrap();
        let resp = self
            .post_with_auth(
                &format!("{}/contribute", self.url),
                "application/json",
                &json_bc,
                &bearer,
            )
            .await?;

        if resp.status() != StatusCode::OK {
            match resp.status() {
                StatusCode::BAD_REQUEST => {
                    return Err(Box::new(CustomError::new("Invalid request.")));
                }

                _ => {
                    return Err(Box::new(CustomError::new(&format!(
                        "Unexpected http code: {}",
                        resp.status()
                    ))));
                }
            }
        }

        let msg: MsgContributeReceipt = resp.json().await?;
        Ok(msg)
    }
}
