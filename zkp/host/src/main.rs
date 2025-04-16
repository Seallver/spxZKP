use vrfy_methods::VRFY_ELF; // It is a binary file of multiply_method 
use risc0_zkvm::{ 
    default_prover, 
    serde::from_slice, 
    ExecutorEnv, 
};
use vrfy_methods::VRFY_ID; 
use rand::Rng;

fn main() {
    // 伪造一个64字节的签名
    let sig: Vec<u8> = rand::thread_rng()
        .sample_iter(rand::distributions::Standard)
        .take(17088)
        .collect();

    // 伪造一个32字节的消息
    let msg: Vec<u8> = vec![
        99, 88, 77, 66, 55, 44, 33, 22,
        11, 0, 9, 8, 7, 6, 5, 4,
        3, 2, 1, 0, 1, 2, 3, 4,
        5, 6, 7, 8, 9, 10, 11, 12
    ];

    // 伪造一个 Keypair（你必须确认这个结构和你定义的 Keypair 是一致的）
    let public: Vec<u8> = vec![0xAA; 32];

    // First, we construct an executor environment
    let env = ExecutorEnv::builder()
        .write(&sig).unwrap() // Passing the input params to environment so it can be used by gues proggram
        .write(&msg).unwrap()
        .write(&public).unwrap()
        .build().unwrap();

    // Obtain the default prover.
    let prover = default_prover();

    // Produce a proveinfo by proving the specified ELF binary.
    let prove_info = prover.prove(env, VRFY_ELF).unwrap();

    // Extract journal of receipt (ie output c, where c = a * b)
    let c: u32 = from_slice(&prove_info.receipt.journal.bytes.as_slice()).unwrap();

    // Print an assertion
    println!(
        "I know the verify of {}, and I can prove it!",
        c
    );

    let _verification = match &prove_info.receipt.verify(VRFY_ID) {
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
