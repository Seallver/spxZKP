#[cfg(all(feature = "sm3", feature = "robust"))]
mod sm3_robust;
#[cfg(all(feature = "sm3", feature = "simple"))]
mod sm3_simple;

#[cfg(all(feature = "sm3", feature = "simple"))]
pub use sm3_simple::*;

#[cfg(all(feature = "sm3", feature = "robust"))]
pub use sm3_robust::*;
