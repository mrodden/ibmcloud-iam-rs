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
use std::time::{Duration, SystemTime};

use jwt::{Header, PKeyWithDigest, RegisteredClaims, Token as JwtToken, VerifyWithKey};
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_with::{
    base64::{Base64, UrlSafe},
    serde_as,
};

use crate::token::Token;

type Error = Box<dyn std::error::Error>;
type Claims = HashMap<String, serde_json::value::Value>;

const EXPIRES_LEEWAY: Duration = Duration::from_secs(5);

pub fn validate_token(token: &Token, endpoint: &str) -> Result<Claims, Error> {
    let jwt: JwtToken<Header, HashMap<String, serde_json::value::Value>, _> =
        JwtToken::parse_unverified(&token.access_token).expect("Unable to parse given token");
    let key_id = jwt
        .header()
        .key_id
        .as_ref()
        .expect("Token has no signing Key ID!");

    // get public key from IAM
    let keys = retrieve_keys(endpoint)?.keys;
    let key = keys
        .iter()
        .find(|&k| k.kid == *key_id)
        .expect("No signing key found for token key id");

    let rsa_key = Rsa::from_public_components(
        BigNum::from_slice(&key.n).unwrap(),
        BigNum::from_slice(&key.e).unwrap(),
    )
    .unwrap();

    // create verifier
    let rs256_verifier = PKeyWithDigest {
        digest: MessageDigest::sha256(),
        key: PKey::from_rsa(rsa_key).unwrap(),
    };

    // verify token
    let reg_claims: RegisteredClaims = token.access_token.verify_with_key(&rs256_verifier)?;

    // verify claims
    _validate_iss(&reg_claims)?;
    _validate_iat(&reg_claims)?;
    _validate_exp(&reg_claims, EXPIRES_LEEWAY)?;

    // return claims
    Ok(jwt.claims().clone())
}

#[derive(Debug, Clone)]
pub struct InvalidTokenError {
    message: String,
}

impl std::fmt::Display for InvalidTokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for InvalidTokenError {}

fn _validate_iss(claims: &RegisteredClaims) -> Result<(), Error> {
    // assert issuer is IAM
    let er = InvalidTokenError {
        message: "Issuer must start with 'https://iam'".to_string(),
    };
    let iss = claims.issuer.as_ref().ok_or(er.clone())?;
    if !iss.starts_with("https://iam") {
        return Err(er.into());
    }
    Ok(())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn _validate_iat(claims: &RegisteredClaims) -> Result<(), Error> {
    // assert issued-at not in future
    let er = InvalidTokenError {
        message: "Issued At is None or in the future".to_string(),
    };
    let iat = claims.issued_at.ok_or(er.clone())?;

    if iat > unix_now() {
        return Err(er.into());
    }

    Ok(())
}

fn _validate_exp(claims: &RegisteredClaims, leeway: std::time::Duration) -> Result<(), Error> {
    // assert not expired with leeway
    let er = InvalidTokenError {
        message: "Expiration is None or in the past".to_string(),
    };
    let exp = claims.expiration.ok_or(er.clone())?;

    if (exp + leeway.as_secs()) < unix_now() {
        return Err(er.into());
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeysResponse {
    keys: Vec<Key>,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Key {
    kty: String,
    kid: String,
    alg: String,
    #[serde_as(as = "Base64<UrlSafe>")]
    n: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe>")]
    e: Vec<u8>,
}

fn retrieve_keys(endpoint: &str) -> Result<KeysResponse, Error> {
    let c = reqwest::blocking::Client::new();

    let resp = c
        .get(format!("{}/identity/keys", endpoint))
        .header("Accept", "application/json")
        .send()
        .expect("Retrieving IAM public keys failed");

    let text = resp.text().expect("Getting body text failed");
    Ok(serde_json::from_str(&text)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn get_test_token() -> Token {
        let access_token = String::from("");
        let refresh_token = String::from("");
        let token_type = String::from("test");

        Token {
            access_token,
            refresh_token,
            token_type,
            expiry: Instant::now() + Duration::from_secs(1200),
        }
    }

    #[test]
    fn test_validate_token() {
        let token = crate::token::TokenManager::default().token().unwrap();

        let c = validate_token(&token, "https://iam.cloud.ibm.com").unwrap();
        println!("{:?}", c);
    }

    #[test]
    fn test_validate_iss() {
        let mut claims = RegisteredClaims::default();
        claims.issuer = None;
        assert!(_validate_iss(&claims).is_err());

        claims.issuer = Some("https://notiam".into());
        assert!(_validate_iss(&claims).is_err());

        claims.issuer = Some("https://iam.test.cloud.ibm.com".into());
        assert!(_validate_iss(&claims).is_ok());
    }

    #[test]
    fn test_validate_iat() {
        let mut claims = RegisteredClaims::default();
        claims.issued_at = None;
        assert!(_validate_iat(&claims).is_err());

        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        // issued_at in future
        claims.issued_at = Some((unix_now + Duration::from_secs(15)).as_secs());
        assert!(_validate_iat(&claims).is_err());

        claims.issued_at = Some((unix_now - Duration::from_secs(15)).as_secs());
        assert!(_validate_iat(&claims).is_ok());
    }

    #[test]
    fn test_validate_exp() {
        let mut claims = RegisteredClaims::default();
        claims.expiration = None;
        assert!(_validate_exp(&claims, EXPIRES_LEEWAY).is_err());

        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        claims.expiration = Some((unix_now - Duration::from_secs(15)).as_secs());
        assert!(_validate_exp(&claims, EXPIRES_LEEWAY).is_err());
    }

    #[test]
    fn test_validate_exp_expired_but_within_leeway() {
        let mut claims = RegisteredClaims::default();
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        claims.expiration = Some((unix_now - Duration::from_secs(15)).as_secs());
        assert!(_validate_exp(&claims, Duration::from_secs(20)).is_ok());
    }

    #[test]
    fn test_validate_exp_token_not_expired() {
        let mut claims = RegisteredClaims::default();
        let unix_now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap();
        claims.expiration = Some((unix_now + Duration::from_secs(15)).as_secs());
        assert!(_validate_exp(&claims, EXPIRES_LEEWAY).is_ok());
    }
}
