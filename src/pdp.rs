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

use crate::token::{Token, TokenManager};

pub struct PDPClient {
    endpoint: String,
    token_manager: TokenManager,
}

pub type Subject = HashMap<String, String>;
pub type Resource = HashMap<String, String>;

#[derive(Debug)]
pub struct AuthorizeResponse {}

impl PDPClient {
    pub fn new(api_key: &str, endpoint: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            token_manager: TokenManager::new(api_key),
        }
    }

    pub fn authorize(
        &self,
        subject: &Subject,
        action: &str,
        resource: &Resource,
    ) -> AuthorizeResponse {
        // FIXME(mrodden): needs impl
        AuthorizeResponse {}
    }
}

pub fn subject_as_attributes(token: &Token, endpoint: &str) -> Subject {
    // FIXME(mrodden): needs impl
    Subject::new()
}
