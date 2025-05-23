use crate::{
    params::*,
    utils::*,
    sm3::*,
    context::SpxCtx
  };
  
  /// Takes an array of inblocks concatenated arrays of SPX_N bytes.
  pub fn thash<const N: usize>(
    out: &mut[u8], input: Option<&[u8]>, ctx: &SpxCtx, addr: &[u32]
  )
    where [(); SPX_N + SPX_SM3_ADDR_BYTES + N * SPX_N]: Sized
  {
    let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];
    let mut buf = [0u8; SPX_N + SPX_SM3_ADDR_BYTES + N * SPX_N];
    let mut bitmask = [0u8; N * SPX_N];
    let mut sm3_state = [0u8; 40]
  ;
    buf[..SPX_N].copy_from_slice(&ctx.pub_seed);
    buf[SPX_N..SPX_N + SPX_SM3_ADDR_BYTES]
      .copy_from_slice(&address_to_bytes(addr)[..SPX_SM3_ADDR_BYTES]);
    mgf1_256(&mut bitmask, N * SPX_N, &buf);
  
    // Retrieve precomputed state containing pub_seed
    sm3_state.copy_from_slice(&ctx.state_seeded[..40]);
  
    for i in 0..N * SPX_N {
        buf[SPX_N + SPX_SM3_ADDR_BYTES + i] = input.unwrap_or(out)[i] ^ bitmask[i];
    }
  
    sm3_inc_finalize(
      &mut outbuf, &mut sm3_state, &buf[SPX_N..], SPX_SM3_ADDR_BYTES + N*SPX_N);
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
  }
  