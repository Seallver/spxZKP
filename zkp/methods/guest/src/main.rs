use risc0_zkvm::guest::env;
use spx_sm3::*;

pub const CRYPTO_MSG_BYTES: usize = 11;
pub const CHUNK :usize = 2048;


fn main() {
    println!("expect sig: {}", CRYPTO_BYTES);
    println!("expect msg: {}", CRYPTO_MSG_BYTES);
    println!("expect pk: {}", CRYPTO_PUBLICKEYBYTES);

    // 从 host 接收 sig
    let msg_vec: Vec<u8> = env::read();
    let public_vec: Vec<u8> = env::read();

    let lastchunk = CRYPTO_BYTES % CHUNK;
    let send_times = if lastchunk != 0 {CRYPTO_BYTES / CHUNK + 1 }else {CRYPTO_BYTES / CHUNK};

    let mut sig_vec: Vec<u8> = Vec::new();

    for _ in 0..send_times {
        let tmp:Vec<u8> = env::read();
        sig_vec.extend(tmp);
    }

    let sig: [u8; CRYPTO_BYTES] = sig_vec.try_into().expect("Wrong length");
    let msg: [u8; CRYPTO_MSG_BYTES] = msg_vec.try_into().expect("Wrong length");
    let public: [u8; CRYPTO_PUBLICKEYBYTES] = public_vec.try_into().expect("Wrong length");

    // 调用 verify 函数
    let result = vrfy(&sig, &msg, &public);
    let valid = result.is_ok();
    env::commit(&valid);

}
