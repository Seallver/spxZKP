
#[cfg(all(feature = "sha2", feature = "robust"))]
mod sha2_robust;
#[cfg(all(feature = "sha2", feature = "simple"))]
mod sha2_simple;

#[cfg(all(feature = "sha2", feature = "simple"))]
pub use sha2_simple::*; 

#[cfg(all(feature = "sha2", feature = "robust"))]
pub use sha2_robust::*; 
