use risc0_zkvm::{default_prover, ExecutorEnv};
use serde::{Deserialize, Serialize};
use std::fs;
use vrfy_methods::{VRFY_ELF, VRFY_ID}; // It is a binary file of multiply_method

#[derive(Debug, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Sm3Signature {
    mlen: u32,
    pk: String,  // Base64 编码的公钥
    Sig: String, // Base64 编码的签名
}

pub const CHUNK :usize = 2048;

fn main() {
    use base64::{engine::general_purpose, Engine as _};

    let json_str = fs::read_to_string("./host/sig.json").unwrap();
    let sig_: Sm3Signature = serde_json::from_str(&json_str).unwrap();
    let pk_bytes = general_purpose::STANDARD.decode(&sig_.pk).unwrap();
    let sig_bytes = general_purpose::STANDARD.decode(&sig_.Sig).unwrap();

    let m_len: usize = sig_.mlen as usize;
    let sm_len: usize = sig_bytes.len();

    let pk = pk_bytes[..].to_vec();
    let m = sig_bytes[sm_len - m_len..].to_vec(); // 消息部分
    let sig = sig_bytes[..sm_len - m_len].to_vec(); // 签名部分

    println!("sig len: {}", sig.len());
    println!("msg len: {}", m.len());
    println!("pk len: {}", pk.len());

    // SPX的签名通常太长，选择分块发送
    let lastchunk = sig.len() % CHUNK;
    let send_times = if lastchunk != 0 {sig.len() / CHUNK + 1 } else {sig.len() / CHUNK};
    
    // First, we construct an executor environment
    let mut env = ExecutorEnv::builder(); // Passing the input params to environment so it can be used by gues proggram
    
    env.write(&m)
    .unwrap()
    .write(&pk)
    .unwrap();
    //分块发送签名
    for t in 0..send_times {
        if lastchunk != 0 && t == send_times - 1 {
            env.write(&sig[CHUNK * t..CHUNK * t + lastchunk].to_vec()).unwrap(); 
            break;
        }
        env.write(&sig[CHUNK * t..CHUNK * (t + 1)].to_vec()).unwrap();    
    }
    let env_= env.build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a proveinfo by proving the specified ELF binary.
    let prove_info = prover.prove(env_, VRFY_ELF).unwrap();

    let receipt = prove_info.receipt;

    #[derive(serde::Deserialize)]
    struct MyData {
        res: u32 
    }

    // Extract journal of receipt
    let c_data: Result<MyData, _> = receipt.journal.decode();

    // Print an assertion
    println!("I know the verify of {}, and I can prove it!", c_data.unwrap().res);

    let _verification = match &receipt.verify(VRFY_ID) {
        Ok(()) => println!("Proof is Valid"),
        Err(_) => println!("Something went wrong !!"),
    };

    print!("cost:\n");
    print!("\tsegments: {}\n", prove_info.stats.segments);
    print!("\tPaging Cycles: {}\n", prove_info.stats.paging_cycles);
    print!("\tReserved Cycles: {}\n", prove_info.stats.reserved_cycles);
    print!("\tUser Cycles: {}\n", prove_info.stats.user_cycles);
    print!("\tTotal Cycles: {}\n", prove_info.stats.total_cycles);

}
