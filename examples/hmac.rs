extern crate ctap_hmac as ctap;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use ctap::extensions::hmac::{FidoHmacCredential, HmacExtension};
use ctap_hmac::{AuthenticatorOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity};
use hex;
use std::env::args;
use std::io::prelude::*;
use std::io::stdin;
use std::io::stdout;

fn main() -> ctap::FidoResult<()> {
    let mut devices = ctap::get_devices()?;
    let device_info = &mut devices.next().expect("No authenicator found");
    let mut device = ctap::FidoDevice::new(device_info)?;
    let options = || Some(AuthenticatorOptions { uv: true, rk: true });
    let mut credential = match args().skip(1).next().map(|h| FidoHmacCredential {
        id: hex::decode(&h).expect("Invalid credential"),
        rp_id: "ctap_demo".into(),
    }) {
        Some(cred) => cred,
        _ => {
            let rp = PublicKeyCredentialRpEntity {
                id: "ctap_demo",
                name: Some("ctap_hmac crate"),
                icon: None,
            };
            let user = PublicKeyCredentialUserEntity {
                id: &[0u8],
                name: "commandline",
                icon: None,
                display_name: None,
            };

            println!("Authorize using your device");
            let credential: FidoHmacCredential = device
                .make_hmac_credential_full(rp, user, &[0u8; 32], &[], options())
                .map(|cred| cred.into())?;
            println!("Credential: {}\nNote: You can pass this credential as first argument in order to reproduce results", hex::encode(&credential.id));
            credential
        }
    };
    let credential = credential;
    print!("Type in your message: ");
    stdout().flush();
    let mut message = String::new();
    stdin()
        .read_line(&mut message)
        .expect("Couldn't get your message\nNote: this demo does not accept binary data");
    println!("Authorize using your device");

    let mut salt = [0u8; 32];
    let mut digest = Sha256::new();
    digest.input(&message.as_bytes());
    digest.result(&mut salt);
    let hash = device
        .get_hmac_assertion(&credential, &salt, None, options())?
        .0;
    println!("Hash: {}", hex::encode(&hash));
    Ok(())
}
