// This file is part of ctap, a Rust implementation of the FIDO2 protocol.
// Copyright (c) Ariën Holthuizen <contact@ardaxi.com>
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.
use cbor_codec::{DecodeError, EncodeError};
use csv_core::{ReadFieldResult, Reader};
use failure::_core::fmt::{Error, Formatter};
use failure::{Backtrace, Context, Fail};
use std::fmt;
use std::fmt::Display;

pub type FidoResult<T> = Result<T, FidoError>;

#[derive(Debug)]
pub struct FidoError(Context<FidoErrorKind>);

#[derive(Debug, Copy, Clone, Fail, Eq, PartialEq)]
pub struct CborErrorCode(u8);

#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum FidoErrorKind {
    #[fail(display = "Read/write error with device.")]
    Io,
    #[fail(display = "Error while reading packet from device.")]
    ReadPacket,
    #[fail(display = "Error while writing packet to device.")]
    WritePacket,
    #[fail(display = "Error while parsing CTAP from device.")]
    ParseCtap,
    #[fail(display = "Error while encoding CBOR for device.")]
    CborEncode,
    #[fail(display = "Error while decoding CBOR from device.")]
    CborDecode,
    #[fail(display = "Packets received from device in the wrong order.")]
    InvalidSequence,
    #[fail(display = "Failed to generate private keypair.")]
    GenerateKey,
    #[fail(display = "Failed to generate shared secret.")]
    GenerateSecret,
    #[fail(display = "Failed to parse public key.")]
    ParsePublic,
    #[fail(display = "Failed to encrypt PIN.")]
    EncryptPin,
    #[fail(display = "Failed to decrypt PIN.")]
    DecryptPin,
    #[fail(display = "Supplied key has incorrect type.")]
    VerifySignature,
    #[fail(display = "Failed to verify response signature.")]
    KeyType,
    #[fail(display = "Device returned error: {}", _0)]
    CborError(CborErrorCode),
    #[fail(display = "Device does not support FIDO2")]
    DeviceUnsupported,
    #[fail(display = "This operating requires a PIN but none was provided.")]
    PinRequired,
}

impl Fail for FidoError {
    fn cause(&self) -> Option<&dyn Fail> {
        self.0.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.0.backtrace()
    }
}

impl Display for FidoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl FidoError {
    pub fn kind(&self) -> FidoErrorKind {
        *self.0.get_context()
    }
}

impl From<FidoErrorKind> for FidoError {
    #[inline(always)]
    fn from(kind: FidoErrorKind) -> FidoError {
        FidoError(Context::new(kind))
    }
}

impl From<Context<FidoErrorKind>> for FidoError {
    fn from(inner: Context<FidoErrorKind>) -> FidoError {
        FidoError(inner)
    }
}

impl From<EncodeError> for FidoError {
    #[inline(always)]
    fn from(err: EncodeError) -> FidoError {
        FidoError(err.context(FidoErrorKind::CborEncode))
    }
}

impl From<DecodeError> for FidoError {
    #[inline(always)]
    fn from(err: DecodeError) -> FidoError {
        FidoError(err.context(FidoErrorKind::CborDecode))
    }
}

impl From<u8> for CborErrorCode {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

impl Display for CborErrorCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        let messages = include_str!("ctap_error_codes.csv");
        let mut rdr = Reader::new();
        let mut bytes = messages.as_bytes();
        let mut col: usize = 0;
        let mut row: usize = 0;
        let mut correct_row: bool = false;
        let mut field = [0u8; 1024];
        let mut name: Option<String> = None;
        let mut desc: Option<String> = None;
        loop {
            let (result, nin, read) = rdr.read_field(&bytes, &mut field);
            bytes = &bytes[nin..];
            match result {
                ReadFieldResult::InputEmpty => {}
                ReadFieldResult::OutputFull => panic!("field too large"),
                ReadFieldResult::Field { record_end } => {
                    let text = String::from_utf8(field[..read].iter().cloned().collect()).unwrap();
                    if row > 0 {
                        match col {
                            0 if i64::from_str_radix(&text[2..], 16)
                                .expect("malformed ctap_error_codes.csv")
                                == self.0 as i64 =>
                            {
                                correct_row = true
                            }
                            1 | 2 if correct_row => {
                                if let Some(_) = name {
                                    desc = Some(text);
                                    break;
                                } else {
                                    name = Some(text);
                                }
                            }
                            _ => (),
                        }
                    }
                    col += 1;
                    if record_end {
                        col = 0;
                        row += 1;
                    }
                }
                ReadFieldResult::End => break,
            }
        }
        if let Some((code, _name, desc)) =
            name.and_then(|name| desc.map(|desc| (self.0, name, desc)))
        {
            write!(f, "CborError: 0x{:x?}: {}", code, desc)?;
        } else {
            write!(f, "CborError: 0x{:x?}", self.0)?;
        }
        Ok(())
    }
}
