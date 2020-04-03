extern crate ctap_hmac as ctap;
use ctap::{
    FidoAssertionRequestBuilder, FidoCredential, FidoCredentialRequestBuilder, FidoDevice,
    FidoResult,
};

use hex;
use std::env::args;

const RP_ID: &str = "ctap_demo";

fn main() -> ctap::FidoResult<()> {
    let mut credentials = args()
        .skip(1)
        .map(|id| FidoCredential {
            id: hex::decode(&id).expect("Invalid credential"),
            public_key: None,
        })
        .collect::<Vec<_>>();
    if credentials.len() == 0 {
        credentials = ctap::get_devices()?
            .map(|h| {
                FidoDevice::new(&h).and_then(|mut dev| {
                    FidoCredentialRequestBuilder::default()
                        .rp_id(RP_ID)
                        .build()
                        .unwrap()
                        .make_credential(&mut dev)
                })
            })
            .collect::<FidoResult<Vec<FidoCredential>>>()?;
    }
    let credentials = credentials.iter().collect::<Vec<_>>();
    let req = FidoAssertionRequestBuilder::default()
        .rp_id(RP_ID)
        .credentials(&credentials[..])
        .build()
        .unwrap();
    let mut devices = ctap::get_devices()?
        .map(|handle| FidoDevice::new(&handle))
        .collect::<FidoResult<Vec<_>>>()?;
    // run with --features request_multiple
    let (cred, _) = ctap::get_assertion_devices(&req, devices.iter_mut())?;
    println!("Success, got assertion for: {}", hex::encode(&cred.id));
    Ok(())
}
