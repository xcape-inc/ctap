use crate::{
    cbor, AuthenticatorOptions, PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity,
};
use crate::{FidoCredential, FidoDevice, FidoErrorKind, FidoResult};
use cbor_codec::value::{Bytes, Int, Key, Text, Value};
use cbor_codec::Encoder;
use cbor_codec::{Config, GenericDecoder};
use rust_crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use rust_crypto::digest::Digest;
use rust_crypto::hmac::Hmac;
use rust_crypto::mac::Mac;
use rust_crypto::sha2::Sha256;
use std::collections::BTreeMap;
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct FidoHmacCredential {
    pub id: Vec<u8>,
    pub rp_id: String,
}

impl From<FidoCredential> for FidoHmacCredential {
    fn from(cred: FidoCredential) -> Self {
        FidoHmacCredential {
            id: cred.id,
            rp_id: cred.rp_id,
        }
    }
}

pub trait HmacExtension {
    fn extension_name() -> &'static str {
        "hmac-secret"
    }

    fn extension_input() -> &'static Value {
        &Value::Bool(true)
    }

    /// Generates data for the extension field as part of the assertion request
    fn get_dict(&mut self, salt: &[u8; 32], salt2: Option<&[u8; 32]>) -> FidoResult<Value> {
        let mut map = BTreeMap::new();
        map.insert(
            Key::Text(Text::Text(
                <Self as HmacExtension>::extension_name().to_owned(),
            )),
            self.get_data(salt, salt2)?,
        );
        Ok(Value::Map(map))
    }

    fn get_data(&mut self, salt: &[u8; 32], salt2: Option<&[u8; 32]>) -> FidoResult<Value>;

    /// Convenience function to create an credential with default rp_id and user_name
    /// Use `FidoDevice::make_credential` if you need more control
    fn make_hmac_credential(&mut self) -> FidoResult<FidoHmacCredential>;

    fn make_hmac_credential_full(
        &mut self,
        rp: cbor::PublicKeyCredentialRpEntity,
        user: cbor::PublicKeyCredentialUserEntity,
        client_data_hash: &[u8],
        exclude_list: &[cbor::PublicKeyCredentialDescriptor],
        options: Option<cbor::AuthenticatorOptions>,
    ) -> FidoResult<FidoCredential>;

    /// Request an assertion from the authenticator for a given credential and salt(s).
    /// at least one `salt` must be provided, consider using a hashing function like SHA256
    /// to ensure that your salt will fit 32 bytes.
    /// Salt(s), credential and the authenticator internal secret will then be used to
    /// generate a secret.
    ///
    /// This method will return the secret whether the assertion matches the credential
    /// provided, and will fail if a PIN is required but not provided or if the
    /// device returns malformed data.
    ///
    fn get_hmac_assertion(
        &mut self,
        credential: &FidoHmacCredential,
        salt: &[u8; 32],
        salt2: Option<&[u8; 32]>,
        options: Option<AuthenticatorOptions>,
    ) -> FidoResult<([u8; 32], Option<[u8; 32]>)>;

    /// Convenience function for `get_hmac_assertion` that will accept arbitrary
    /// lenght input which will then be hashed and passed on
    fn hmac_challange(
        &mut self,
        credential: &FidoHmacCredential,
        input: &[u8],
    ) -> FidoResult<[u8; 32]> {
        let mut salt = [0u8; 32];
        let mut digest = Sha256::new();
        digest.input(input);
        digest.result(&mut salt);
        self.get_hmac_assertion(
            credential,
            &salt,
            None,
            Some(AuthenticatorOptions { uv: true, rk: true }),
        )
        .map(|secret| secret.0)
    }
}

impl HmacExtension for FidoDevice {
    fn get_data(&mut self, salt: &[u8; 32], salt2: Option<&[u8; 32]>) -> FidoResult<Value> {
        let shared_secret = self.shared_secret.as_ref().unwrap();
        let mut encryptor = shared_secret.encryptor();
        let mut salt_enc = [0u8; 64];
        let mut output = RefWriteBuffer::new(&mut salt_enc);
        let mut encrypt = || {
            encryptor.encrypt(&mut RefReadBuffer::new(salt), &mut output, salt2.is_none())?;
            if let Some(salt2) = salt2 {
                encryptor
                    .encrypt(&mut RefReadBuffer::new(salt2), &mut output, true)
                    .map(|_| ())
            } else {
                Ok(())
            }
        };
        encrypt().map_err(|_| FidoErrorKind::Io)?;

        let key_agreement = || {
            let mut cur = Cursor::new(Vec::new());
            let mut encoder = Encoder::new(&mut cur);
            shared_secret.public_key.encode(&mut encoder).unwrap();
            cur.set_position(0);
            let mut dec = GenericDecoder::new(Config::default(), cur);
            dec.value()
        };

        let mut map = BTreeMap::new();
        map.insert(
            Key::Int(Int::from_i64(0x01)),
            key_agreement().map_err(|_| FidoErrorKind::Io)?,
        );
        map.insert(
            Key::Int(Int::from_i64(0x02)),
            Value::Bytes(Bytes::Bytes(
                salt_enc[0..((salt2.is_some() as usize + 1) * 32)].to_vec(),
            )),
        );

        let mut salt_hmac = Hmac::new(Sha256::new(), &shared_secret.shared_secret);
        salt_hmac.input(&salt_enc[0..((salt2.is_some() as usize + 1) * 32)]);

        let mut authed_salt_enc = [0u8; 32];
        authed_salt_enc.copy_from_slice(salt_hmac.result().code());

        map.insert(
            Key::Int(Int::from_i64(0x03)),
            Value::Bytes(Bytes::Bytes(authed_salt_enc[0..16].to_vec())),
        );

        Ok(Value::Map(map))
    }

    fn make_hmac_credential(&mut self) -> FidoResult<FidoHmacCredential> {
        let rp = PublicKeyCredentialRpEntity {
            id: "hmac",
            name: None,
            icon: None,
        };
        let user = PublicKeyCredentialUserEntity {
            id: &[0u8],
            name: "commandline",
            icon: None,
            display_name: None,
        };
        let options = Some(AuthenticatorOptions {
            uv: true,
            rk: false,
        });

        self.make_hmac_credential_full(rp, user, &[0u8; 32], &[], options)
            .map(|cred| cred.into())
    }

    fn make_hmac_credential_full(
        &mut self,
        rp: cbor::PublicKeyCredentialRpEntity,
        user: cbor::PublicKeyCredentialUserEntity,
        client_data_hash: &[u8],
        exclude_list: &[cbor::PublicKeyCredentialDescriptor],
        options: Option<cbor::AuthenticatorOptions>,
    ) -> FidoResult<FidoCredential> {
        self.make_credential_full(
            rp,
            user,
            client_data_hash,
            exclude_list,
            &[(
                <Self as HmacExtension>::extension_name(),
                <Self as HmacExtension>::extension_input(),
            )],
            options,
        )
    }

    fn get_hmac_assertion(
        &mut self,
        credential: &FidoHmacCredential,
        salt: &[u8; 32],
        salt2: Option<&[u8; 32]>,
        options: Option<AuthenticatorOptions>,
    ) -> FidoResult<([u8; 32], Option<[u8; 32]>)> {
        let client_data_hash = [0u8; 32];
        while self.shared_secret.is_none() {
            self.init_shared_secret()?;
        }
        if self.needs_pin && self.pin_token.is_none() {
            Err(FidoErrorKind::PinRequired)?
        }

        if client_data_hash.len() != 32 {
            Err(FidoErrorKind::CborEncode)?
        }
        let pin_auth = self
            .pin_token
            .as_ref()
            .map(|token| token.auth(&client_data_hash));
        let ext_data: Value = self.get_data(salt, salt2)?;
        let allow_list = [cbor::PublicKeyCredentialDescriptor {
            cred_type: String::from("public-key"),
            id: credential.id.clone(),
        }];
        let request = cbor::GetAssertionRequest {
            rp_id: &credential.rp_id,
            client_data_hash: &client_data_hash,
            allow_list: &allow_list,
            extensions: &[(<Self as HmacExtension>::extension_name(), &ext_data)],
            options: options,
            pin_auth,
            pin_protocol: pin_auth.and(Some(0x01)),
        };
        let response = match self.cbor(cbor::Request::GetAssertion(request))? {
            cbor::Response::GetAssertion(resp) => resp,
            _ => Err(FidoErrorKind::CborDecode)?,
        };
        let shared_secret = self.shared_secret.as_ref().unwrap();
        let mut decryptor = shared_secret.decryptor();
        let mut hmac_secret_combined = [0u8; 64];
        let _output = RefWriteBuffer::new(&mut hmac_secret_combined);
        let hmac_secret_enc = match response
            .auth_data
            .extensions
            .get(<Self as HmacExtension>::extension_name())
            .ok_or(FidoErrorKind::CborDecode)?
        {
            Value::Bytes(hmac_ciphered) => Ok(match hmac_ciphered {
                Bytes::Bytes(hmac_ciphered) => hmac_ciphered.to_vec(),
                Bytes::Chunks(hmac_ciphered) => hmac_ciphered.iter().fold(Vec::new(), |s, i| {
                    let mut s = s;
                    s.extend_from_slice(&i);
                    s
                }),
            }),
            _ => Err(FidoErrorKind::CborDecode),
        }?;
        let mut hmac_secret = [0u8; 64];
        decryptor
            .decrypt(
                &mut RefReadBuffer::new(&hmac_secret_enc),
                &mut RefWriteBuffer::new(&mut hmac_secret),
                true,
            )
            .map_err(|_| FidoErrorKind::ReadPacket)?;
        let mut hmac_secret_0 = [0u8; 32];
        let mut hmac_secret_1 = [0u8; 32];
        hmac_secret_0.copy_from_slice(&hmac_secret[0..32]);
        hmac_secret_1.copy_from_slice(&hmac_secret[32..]);
        Ok((hmac_secret_0, salt2.map(|_| hmac_secret_1)))
    }
}