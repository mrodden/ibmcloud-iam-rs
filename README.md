# ibmcloud-iam-rs
A collection of Rust modules for interacting with IBM Cloud IAM (Identity and Access Managment)

Current features:
  - Requesting IAM access tokens via an intelligent and thread safe caching mechanism (`TokenManager`)
  - Validating IAM access tokens and inspecting the claims within
  - Authorizing user actions via Subject, Action, Resource requests to the PDP IAM service

# Usage

## Using the TokenManager to retrieve access tokens
```rust
use ibmcloud_iam::token::{TokenManager, DEFAULT_IAM_ENDPOINT};

// grab an API key from environment variables to use for token getting purposes
let api_key = std::env::var("IBMCLOUD_API_KEY").unwrap();
let tm = TokenManager::new(&api_key, DEFAULT_IAM_ENDPOINT);

// now whenever an access token is needed, call `tm.token()`
// this will return a cached non-expired Token if possible,
// otherwise it will request a new token from IAM, cache it, and return it

// gets a new Token, since none has been retrieved yet
let tok1 = tm.token().unwrap();

// returns the same Token as above, since it is cached and not expired
let tok2 = tm.token().unwrap();

assert_eq!(tok1, tok2);

// the Bearer token is available on the Token struct as 'access_token'
let bearer_token = format!("Bearer {}", tok1.access_token);
```

## Parsing and Validating Tokens

```rust
use ibmcloud_iam::token::TokenManager;
use ibmcloud_iam::jwt::validate_token;

// lazy way of getting a TokenManager with the
// API key from 'IBMCLOUD_API_KEY' in your environment vars
let tm = TokenManager::default();
let token = tm.token().unwrap();

// base url of the IAM endpoint you'll be using to validate tokens
let endpoint = "https://iam.cloud.ibm.com";

// validate the token signature, expiration, issuer, and issued_at claims, and return all the claims
let claims = validate_token(&token, &endpoint).unwrap();

println!("{:#?}", claims);
```

## Authorizing User Actions via PDP

Please see [pdp_auth.rs](examples/pdp_auth.rs) in `examples` for a demonstration on how to interact with PDP
