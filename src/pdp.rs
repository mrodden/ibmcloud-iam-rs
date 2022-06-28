// Copyright 2022 Mathew Odden <mathewrodden@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::value::Value;

use crate::token::{Token, TokenManager};
use crate::error::Error;

pub struct PDPClient {
    endpoint: String,
    token_manager: TokenManager,
}

pub type Resource = HashMap<String, String>;

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthorizeRequestBody(Vec<AuthorizeRequest>);

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthorizeRequest{
    subject: Subject,
    action: String,
    resource: ResourceAttrs,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject{
    access_token_body: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ResourceAttrs {
    attributes: HashMap<String, String>
}

impl From<Resource> for ResourceAttrs {
    fn from(r: Resource) -> ResourceAttrs {
        ResourceAttrs { attributes: r }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthorizeResponseBody {
    responses: Vec<AuthorizeResponse>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct AuthorizeResponse {
    #[serde(rename="authorizationDecision")]
    pub decision: AuthorizationDecision,

    status: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthorizationDecision {
    permitted: bool,
    reason: Option<String>,
    obligation: Option<Obligation>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Obligation {
    actions: Vec<String>,
    max_cache_age_seconds: u64,
    subject: SubjectAttrs,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct SubjectAttrs {
    attributes: HashMap<String, Value>,
}


impl PDPClient {
    pub fn new(api_key: &str, endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            token_manager: TokenManager::new(api_key, endpoint),
        }
    }

    pub fn authorize(
        &self,
        subject: Subject,
        action: &str,
        resource: Resource,
    ) -> Result<AuthorizationDecision, Error> {

        let authreq = AuthorizeRequest {
            subject: subject,
            action: action.to_string(),
            resource: resource.into(),
        };

        let req_body = serde_json::to_string(&AuthorizeRequestBody(vec!(authreq))).unwrap();

        let c = reqwest::blocking::Client::new();

        let path = format!("{}/v2/authz", self.endpoint);

        let token = self.token_manager.token()?.access_token;

        let resp = c
            .post(path)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", token))
            .body(req_body)
            .send()
            .expect("PDP Authorize request failed");

        let status = resp.status();
        let text = resp.text().expect("Getting body text failed");

        if !status.is_success() {
            return Err(format!("Authz request failed: status='{}', body='{}'", status, text).into());
        }

        let mut resp_body = match serde_json::from_str::<AuthorizeResponseBody>(&text) {
            Ok(v) => v,
            Err(_) => {
                return Err(
                    format!("Unexpected response from PDP: status='{}', body='{}'", status, text)
                    .into()
                );
            },
        };

        Ok(resp_body.responses.remove(0).decision)
    }
}

pub fn subject_from_token(token: &Token) -> Subject {
    let parts: Vec<&str> = token.access_token.split(".").collect();
    Subject{access_token_body: parts[1].to_string()}
}
