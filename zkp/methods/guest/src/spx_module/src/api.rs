use crate::params::{CRYPTO_PUBLICKEYBYTES, CRYPTO_SECRETKEYBYTES};
use crate::sign::*;

#[derive(Copy, Clone)]
pub struct Keypair {
    pub public: [u8; CRYPTO_PUBLICKEYBYTES],
    pub secret: [u8; CRYPTO_SECRETKEYBYTES],
}

pub enum SigError {
    Input,
    Verify,
}

/// Verify signature using keypair
///
/// Example:
/// ```no_run
/// # use pqc_sphincsplus::*;
/// # let keys = keypair();
/// # let msg = [0u8; 32];
/// # let sig = sign(&msg, &keys);
/// let sig_verify = verify(&sig, &msg, &keys);
/// assert!(sig_verify.is_ok());
pub fn verify(sig: &[u8], msg: &[u8], keypair: &Keypair) -> Result<(), SigError> {
    crypto_sign_verify(&sig, &msg, &keypair.public)
}

pub fn vrfy(sig: &[u8], msg: &[u8], pk: &[u8]) -> Result<(), SigError> {
    crypto_sign_verify(&sig, &msg, &pk)
}
