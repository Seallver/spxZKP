use multiply_methods::MULTIPLY_ELF; // It is a binary file of multiply_method 
use risc0_zkvm::{ 
    default_prover, 
    serde::from_slice, 
    ExecutorEnv, 
};
use multiply_methods::MULTIPLY_ID; 

fn main() { 
    
    // Declaring our secret input params 
    let a: u64 = 17; 
    let b: u64 = 23; 
    
    // First, we construct an executor environment 
    let env = ExecutorEnv::builder()
     .write(&a).unwrap() // Passing the input params to environment so it can be used by gues proggram 
     .write(&b).unwrap() 
     .build().unwrap(); 
    
    // Obtain the default prover. 
    let prover = default_prover(); 
    
    // Produce a proveinfo by proving the specified ELF binary. 
    let prove_info = prover.prove(env, MULTIPLY_ELF).unwrap(); 

    // Extract journal of receipt (ie output c, where c = a * b) 
    let c: u64 = from_slice(&prove_info.receipt.journal.bytes.as_slice()).unwrap(); 
    
    // Print an assertion 
    println!("Hello, world! I know the factors of {}, and I can prove it!", c); 

    let _verification = match &prove_info.receipt.verify(MULTIPLY_ID){ 
        Ok(()) => println!("Proof is Valid"), 
        Err(_) => println!("Something went wrong !!"), 
    }; 

    print!("cost:\n");
    print!("segments: {}\n", prove_info.stats.segments);
    print!("Paging Cycles: {}\n", prove_info.stats.paging_cycles);
    print!("Reserved Cycles: {}\n", prove_info.stats.reserved_cycles);
    print!("User Cycles: {}\n", prove_info.stats.user_cycles);
    print!("Total Cycles: {}\n", prove_info.stats.total_cycles);

}