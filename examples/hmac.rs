extern crate ctap_hmac as ctap;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use ctap::extensions::hmac::HmacExtension;
use ctap::{FidoAssertionRequestBuilder, FidoCredential, FidoCredentialRequestBuilder};
use hex;
use std::env;
use std::io::prelude::*;
use std::io::stdin;
use std::io::stdout;

const RP_ID: &str = "ctap_demo";

fn main() -> ctap::FidoResult<()> {
    let mut devices = ctap::get_devices()?;
    let device_info = &mut devices.next().expect("No authenticator found");
    let mut device = ctap::FidoDevice::new(device_info)?;
    match env::var("CTAP_PIN") {
        Ok(ctap_pin) => {
            device.unlock(&ctap_pin).unwrap()
        }
        Err(_) => {}
    }

    let credential = match env::args().skip(1).next().map(|h| FidoCredential {
        id: hex::decode(&h).expect("Invalid credential"),
        public_key: None,
    }) {
        Some(cred) => cred,
        _ => {
            let req = FidoCredentialRequestBuilder::default()
                .rp_id(RP_ID)
                .rp_name("ctap_hmac crate")
                .user_name("example")
                .uv(false)
                .build()
                .unwrap();

            println!("Authorize using your device");
            let cred = device
                .make_hmac_credential(&req)
                .expect("Failed to request credential");
            println!("Credential: {}\nNote: You can pass this credential as first argument in order to reproduce results", hex::encode(&cred.id));
            cred
        }
    };
    print!("Type in your message: ");
    stdout().flush().unwrap();
    let mut message = String::new();
    stdin()
        .read_line(&mut message)
        .expect("Couldn't get your message\nNote: this demo does not accept binary data");
    println!("Authorize using your device");

    let mut salt = [0u8; 32];
    let mut digest = Sha256::new();
    digest.input(&message.as_bytes());
    digest.result(&mut salt);
    let credential = &&credential;
    let request = FidoAssertionRequestBuilder::default()
        .rp_id(RP_ID)
        .credential(credential)
        .build()
        .unwrap();
    let (_cred, (hash1, _hash2)) = device.get_hmac_assertion(&request, &salt, None)?;
    println!("Hash: {}", hex::encode(&hash1));
    Ok(())
}
