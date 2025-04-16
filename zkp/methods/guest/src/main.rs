use risc0_zkvm::guest::env;
use spx_sm3::*;

pub const CRYPTO_MSG_BYTES: usize = 32;

fn main() {
    // 从 host 接收 sig
    let sig_vec: Vec<u8> = env::read();
    let sig: [u8; CRYPTO_BYTES] = sig_vec.try_into().expect("Wrong length"); 
    
    // 从 host 接收 msg
    let msg_vec: Vec<u8> = env::read();
    let msg: [u8; CRYPTO_MSG_BYTES] = msg_vec.try_into().expect("Wrong length"); 
    
    // 从 host 接收 public key
    let public_vec: Vec<u8> = env::read();
    let public: [u8; CRYPTO_PUBLICKEYBYTES] = public_vec.try_into().expect("Wrong length");
    
    let secret: [u8; CRYPTO_SECRETKEYBYTES] = [0x00; 64];

    // 构造 Keypair
    let keys = Keypair {
        public,
        secret,
    };

    // 调用 verify 函数
    let result = verify(&sig, &msg, &keys);
    let valid = result.is_ok();
    env::commit(&valid);
}
