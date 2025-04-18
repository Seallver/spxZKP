use crate::{context::SpxCtx, params::*, sm3::*, utils::*};

/// Takes an array of inblocks concatenated arrays of SPX_N bytes.
pub fn thash<const N: usize>(out: &mut [u8], input: Option<&[u8]>, ctx: &SpxCtx, addr: &[u32])
where
    [(); SPX_N + SPX_SM3_ADDR_BYTES + N * SPX_N]: Sized,
{
    let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];
    let mut sm3_state = [0u8; 40];
    let mut buf = [0u8; SPX_N + SPX_SM3_ADDR_BYTES + N * SPX_N];

    // Retrieve precomputed state containing pub_seed
    sm3_state.copy_from_slice(&ctx.state_seeded);

    buf[..SPX_SM3_ADDR_BYTES].copy_from_slice(&address_to_bytes(&addr)[..SPX_SM3_ADDR_BYTES]);
    buf[SPX_SM3_ADDR_BYTES..SPX_SM3_ADDR_BYTES + N * SPX_N]
        .copy_from_slice(&input.unwrap_or(out)[..N * SPX_N]);

    sm3_inc_finalize(
        &mut outbuf,
        &mut sm3_state,
        &buf,
        SPX_SM3_ADDR_BYTES + N * SPX_N,
    );
    out[..SPX_N].copy_from_slice(&outbuf[..SPX_N]);
}
