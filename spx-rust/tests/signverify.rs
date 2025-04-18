use pqc_sphincsplus::*;
use std::fs;
use serde::{Deserialize, Serialize};


#[derive(Debug, Serialize, Deserialize)]
pub struct Sm3Signature {
    mlen: u32,
    pk: String,         // Base64 编码的公钥
    Sig: String,        // Base64 编码的签名
}


#[test]
#[cfg(all(
  any(feature = "haraka", feature = "shake", feature = "sha2", feature = "sm3"),
  any(feature = "f128", feature = "f192", feature = "f256",
      feature = "s128", feature = "s192", feature = "s256"),
  any(feature = "robust", feature = "simple") 
))]
fn valid_sig() {
  let keys = keypair();
  let msg = [27u8; 64];
  let sig = sign(&msg, &keys);
  let sig_verify = verify(&sig, &msg, &keys);
  assert!(sig_verify.is_ok());
}


#[test]
#[cfg(all(
  any(feature = "haraka", feature = "shake", feature = "sha2", feature = "sm3"),
  any(feature = "f128", feature = "f192", feature = "f256",
      feature = "s128", feature = "s192", feature = "s256"),
  any(feature = "robust", feature = "simple") 
))]
fn invalid_sig() {
  let keys = keypair();
  let msg = [27u8; 64];
  let mut sig = sign(&msg, &keys);
  sig[..4].copy_from_slice(&[255; 4]);
  let sig_verify = verify(&sig, &msg, &keys);
  assert!(sig_verify.is_err());
}

#[test]
#[cfg(all(feature = "sm3", feature = "s128", feature = "simple"))]
fn vrfy_json_msg() {
  use base64::{Engine as _, engine::general_purpose};

  let json_str = fs::read_to_string("./tests/sig.json").unwrap();
  let sig: Sm3Signature = serde_json::from_str(&json_str).unwrap();
  let pk_bytes = general_purpose::STANDARD.decode(&sig.pk).unwrap();
  let sig_bytes = general_purpose::STANDARD.decode(&sig.Sig).unwrap();

  let m_len : usize = sig.mlen as usize;

  let pk_len : usize = pk_bytes.len();
  assert!(pk_len == CRYPTO_PUBLICKEYBYTES);

  let sm_len : usize = sig_bytes.len();
  assert!(sm_len == CRYPTO_BYTES + m_len as usize);

  let sig_vec = sig_bytes.to_vec();
  let pk = pk_bytes[..].to_vec();
  let m = &sig_vec[sm_len  - m_len ..];  // 消息部分
  let sm = &sig_vec[.. sm_len - m_len ]; // 签名部分

  let sig_verify = vrfy(&sm, &m, &pk);
  assert!(sig_verify.is_ok());
}