use crate::params::SPX_N;

/// Sphincs context
pub struct SpxCtx {
  pub pub_seed: [u8; SPX_N],
  
  #[cfg(feature="sha2")]
  pub state_seeded: [u8; 40],
}

impl Default for SpxCtx {
  fn default() -> Self {
      Self { 
        pub_seed: [0u8; SPX_N], 

        #[cfg(feature="sha2")]
        state_seeded: [0u8; 40],
    }
  }
}
