use ibmcloud_iam::jwt::validate_token;
use ibmcloud_iam::pdp as pdpapi;
use ibmcloud_iam::pdp::{Resource, Subject};
use ibmcloud_iam::token::TokenManager;

pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // production IAM endpoint
    let endpoint = "https://iam.cloud.ibm.com";

    // get a user token from IAM
    // normally this would be something your web service or server would receive from a user
    // but we grab one here for the sake of completeness
    let api_key =
        std::env::var("IBMCLOUD_API_KEY").expect("Could not read IBMCLOUD_API_KEY from env");
    let tm = TokenManager::new(&api_key);
    let user_token = tm.token()?;

    // validate user token, this checks the signature and returns claims
    let claims = validate_token(&user_token, &endpoint);

    // Service ID API key, this is unique to your web service/server
    let service_id_key =
        std::env::var("SERVICE_ID_KEY").expect("Could not parse SERVICE_ID_KEY from env");

    // build PDP client object for interacting with the IAM PDP endpoint
    let pdp = pdpapi::PDPClient::new(&service_id_key, &endpoint);

    // get subject attributes from user token.
    // this will also validate the token internally
    let sub = pdpapi::subject_as_attributes(&user_token, &endpoint);

    // action on the resource to be authorized
    let action = "books.dashboard.view";

    // create Resource object for PDP authorization request
    // this is specific to your web service/server and should
    // match up with the Attributes allowed in your IAM Service definition
    let mut resource = Resource::new();
    [
        ("serviceName", "books"),
        ("accountId", "1111222233334444"),
        ("ctype", "public"),
        ("serviceInstance", "9e386139-0000-000-8101-103771fa7793"),
    ]
    .iter()
    .for_each(|tup| {
        resource.insert(tup.0.to_string(), tup.1.to_string());
    });

    // build the final request, send to IAM, get and return the response
    let resp = pdp.authorize(&sub, &action, &resource);

    println!("Authorization Response: {:?}", resp);

    Ok(())
}
