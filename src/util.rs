#[cfg(feature = "request_multiple")]
use crate::{
    cbor::AuthenticatorData, FidoAssertionRequest, FidoCredential, FidoCredentialRequest,
    FidoDevice, FidoErrorKind, FidoResult,
};
#[cfg(feature = "request_multiple")]
use crossbeam::thread;
#[cfg(feature = "request_multiple")]
use std::sync::mpsc::channel;

#[cfg(feature = "request_multiple")]
pub fn request_multiple_devices<
    'a,
    T: Send + 'a,
    F: Fn(&mut FidoDevice) -> FidoResult<T> + 'a + Sync,
>(
    devices: impl Iterator<Item = (&'a mut FidoDevice, &'a F)>,
) -> FidoResult<T> {
    thread::scope(|scope| -> FidoResult<T> {
        let (tx, rx) = channel();
        let handles = devices
            .map(|(device, fn_)| {
                let cancel = device.cancel_handle()?;
                let tx = tx.clone();
                let thread_handle = scope.spawn(move |_| tx.send(fn_(device)));
                Ok((cancel, thread_handle))
            })
            .collect::<FidoResult<Vec<_>>>()?;

        let mut err = None;
        for res in rx.iter().take(handles.len()) {
            match res {
                Ok(_) => {
                    for (mut cancel, join) in handles {
                        // Canceling out of courtesy don't care if it fails
                        let _ = cancel.cancel();
                        let _ = join.join();
                    }
                    return res;
                }
                e => err = Some(e),
            }
        }
        err.unwrap_or(Err(FidoErrorKind::DeviceUnsupported.into()))
    })
    .unwrap()
}

/// Will send the `assertion_request` to all supplied `devices` and return either the first successful assertion or the last error
#[cfg(feature = "request_multiple")]
pub fn get_assertion_devices<'a>(
    assertion_request: &'a FidoAssertionRequest,
    devices: impl Iterator<Item = &'a mut FidoDevice>,
) -> FidoResult<(&'a FidoCredential, AuthenticatorData)> {
    let get_assertion = |device: &mut FidoDevice| device.get_assertion(assertion_request);
    request_multiple_devices(devices.map(|device| (device, &get_assertion)))
}

/// Will send the `credential_request` to all supplied `devices` and return either the first credential or the last error
#[cfg(feature = "request_multiple")]
pub fn make_credential_devices<'a>(
    credential_request: &'a FidoCredentialRequest,
    devices: impl Iterator<Item = &'a mut FidoDevice>,
) -> FidoResult<FidoCredential> {
    let make_credential = |device: &mut FidoDevice| device.make_credential(credential_request);
    request_multiple_devices(devices.map(|device| (device, &make_credential)))
}
