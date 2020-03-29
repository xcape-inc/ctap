extern crate ctap_hmac as ctap;

use crypto::digest::Digest;
use crypto::sha2::Sha256;
use ctap::{FidoCredential, FidoCredentialRequestBuilder, FidoAssertionRequestBuilder, AuthenticatorOptions, FidoDevice, FidoError, FidoResult};
use failure::_core::time::Duration;
use hex;
use std::env::args;
use std::io::prelude::*;
use std::io::stdin;
use std::io::stdout;
use std::sync::mpsc::channel;
use std::sync::Mutex;
use crossbeam::thread;

const RP_ID: &str = "ctap_demo";

fn run() -> ctap::FidoResult<()> {
    let mut credentials = args().skip(1).map(|id| FidoCredential {
        id: hex::decode(&id).expect("Invalid credential"),
        public_key: None,
    }).collect::<Vec<_>>();
    if credentials.len() == 0 {
        credentials = ctap::get_devices()?.map(|h| FidoDevice::new(&h).and_then(|mut dev| FidoCredentialRequestBuilder::default()
            .rp_id(RP_ID).build().unwrap().make_credential(&mut dev))).collect::<FidoResult<Vec<FidoCredential>>>()?;
    }
    let credentials = credentials.iter().collect::<Vec<_>>();
    let (s, r) = channel();
    thread::scope(|scope| {
        let handles = ctap::get_devices()?.map(|h| {
            let req = FidoAssertionRequestBuilder::default().rp_id(RP_ID).credentials(&credentials[..]).build().unwrap();
            let s = s.clone();
            scope.spawn(move |_| {
                FidoDevice::new(&h).and_then(|mut dev| {
                    req.get_assertion(&mut dev).map(|res| {
                        s.send(res.clone());
                        res
                    })
                })
            })
        }).collect::<Vec<_>>();
        for h in handles {
            h.join();
        }
        Ok::<(), FidoError>(())
    }).unwrap();
    for res in r.iter().take(credentials.len()) {
        dbg!(res);
    }
    Ok(())
}

fn main() {
    dbg!(run());
}
