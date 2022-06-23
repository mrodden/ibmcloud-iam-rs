
use tracing::debug;
use tracing_subscriber;

use ibmcloud_iam::token::TokenManager;

pub fn main() {
    tracing_subscriber::fmt::init();

    let iam = TokenManager::default();

    let token = iam.token().unwrap();
    debug!("Token: {:?}", token);
    println!("AccessToken: {}", token.access_token);
}
