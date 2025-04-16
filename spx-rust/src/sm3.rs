use core::convert::TryInto;
use crate::context::SpxCtx;
use crate::params::*;
use crate::utils::*;
use sha256::digest::generic_array::GenericArray;

pub const SPX_SM3_BLOCK_BYTES: usize = 64;
pub const SPX_SM3_OUTPUT_BYTES: usize = 32;  /* This does not necessarily equal SPX_N */

pub const SPX_SM3_ADDR_BYTES: usize = 22;


const IV_256: [u8; 32] = [
  0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
  0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
  0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
  0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
];



pub fn load_bigendian_32(x: &[u8]) -> u32 {
  u32::from_be_bytes(x[..4].try_into().unwrap())
}

pub fn load_bigendian_64(x: &[u8]) -> u64 {
  u64::from_be_bytes(x[..8].try_into().unwrap())
}

pub fn store_bigendian_32(x: &mut[u8], u: u32) {
  x[..4].copy_from_slice(&u.to_be_bytes());
}

pub fn store_bigendian_64(x: &mut[u8], u: u64) {
  x[..8].copy_from_slice(&u.to_be_bytes());
}

fn crypto_hashblocks_sm3(
  statebytes: &mut [u8], input: &[u8], mut inlen: usize
) -> usize  
{
  let mut state = [0u32; 8];
  let mut idx = 0;

  for i in 0..8 {
    state[i] = load_bigendian_32(&statebytes[i*4..]);
  }

  while inlen >= 64 {
    let arr = GenericArray::from_slice(&input[idx..idx+64]);
    sha256::compress256(&mut state, &[*arr]);
    idx += 64;
    inlen -= 64;
  }

  for i in 0..8 {
    store_bigendian_32(&mut statebytes[i*4..], state[i]);
  }

  return inlen;
}


pub fn sm3_inc_init(state: &mut[u8]) {
  for i in 0..32 {
    state[i] = IV_256[i];
  }
  for i in 32..40 {
    state[i] = 0;
  }
}

pub fn sm3_inc_blocks(state: &mut [u8], input: &[u8], inblocks: usize) {
  let mut bytes = load_bigendian_64(&state[32..]);
  crypto_hashblocks_sm3(state, input, 64 * inblocks);
  bytes += 64 * inblocks as u64;
  store_bigendian_64(&mut state[32..], bytes);
}


pub fn sm3_inc_finalize(out: &mut[u8], state: &mut[u8], input: &[u8], mut inlen: usize) {
  let mut padded = [0u8; 128];
  let bytes = load_bigendian_64(&state[32..]) + inlen as u64;

  crypto_hashblocks_sm3(state, input, inlen);
  let mut idx = 0;
  idx += inlen;
  inlen &= 63;
  idx -= inlen;

  padded[..inlen].copy_from_slice(&input[idx..idx+inlen]);
  padded[inlen as usize] = 0x80;

  if inlen < 56 {
    padded[(inlen+1)..56].fill(0);
    padded[56] = (bytes >> 53) as u8;
    padded[57] = (bytes >> 45) as u8;
    padded[58] = (bytes >> 37) as u8;
    padded[59] = (bytes >> 29) as u8;
    padded[60] = (bytes >> 21) as u8;
    padded[61] = (bytes >> 13) as u8;
    padded[62] = (bytes >> 5) as u8;
    padded[63] = (bytes << 3) as u8;
    crypto_hashblocks_sm3(state, &padded, 64);
  } else {
    padded[(inlen+1)..120].fill(0);
    padded[120] = (bytes >> 53) as u8;
    padded[121] = (bytes >> 45) as u8;
    padded[122] = (bytes >> 37) as u8;
    padded[123] = (bytes >> 29) as u8;
    padded[124] = (bytes >> 21) as u8;
    padded[125] = (bytes >> 13) as u8;
    padded[126] = (bytes >> 5) as u8;
    padded[127] = (bytes << 3) as u8;
    crypto_hashblocks_sm3(state, &padded, 128);
  }
  out[..32].copy_from_slice(&state[..32]);
}


pub fn sm3(out: &mut [u8], input: &[u8], inlen: usize) {
  let mut state = [0u8; 40];
  sm3_inc_init(&mut state);
  sm3_inc_finalize(out, &mut state, input, inlen);
}

/// mgf1 function based on the SHA-256 hash function
/// Note that inlen should be sufficiently small that it still allows for
/// an array to be allocated on the stack. Typically 'input' is merely a seed.
/// Outputs outlen number of bytes
#[cfg(feature = "robust")]
pub fn mgf1_256(out: &mut[u8], outlen: usize, input: &[u8])
{
  const INLEN: usize = SPX_N + SPX_SM3_ADDR_BYTES;
  let mut inbuf = [0u8; INLEN + 4];
  let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];

  inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

  // While we can fit in at least another full block of SM3 output..
  let mut i = 0;
  let mut idx = 0;
  while (i+1)*SPX_SM3_OUTPUT_BYTES <= outlen {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sm3(&mut out[idx..], &inbuf, INLEN + 4);
    idx += SPX_SM3_OUTPUT_BYTES;
    i += 1;
  }
  // Until we cannot anymore, and we fill the remainder.
  if outlen > i*SPX_SM3_OUTPUT_BYTES {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sm3(&mut outbuf, &inbuf, INLEN + 4);
    let end = outlen - i*SPX_SM3_OUTPUT_BYTES;
    out[idx..idx+end].copy_from_slice(&outbuf[..end]);
  }
}


/// Absorb the constant pub_seed using one round of the compression function
/// This initializes state_seeded , which can then be
/// reused input thash
pub fn seed_state(ctx: &mut SpxCtx) {
  let mut block = [0u8; SPX_SM3_BLOCK_BYTES];

  block[..SPX_N].copy_from_slice(&ctx.pub_seed[..SPX_N]);
  block[SPX_N..SPX_SM3_BLOCK_BYTES].fill(0);

  // block has been properly initialized for SHA-256 
  sm3_inc_init(&mut ctx.state_seeded);
  sm3_inc_blocks(&mut ctx.state_seeded, &block, 1);
}

// TODO: Refactor and get rid of code duplication
// inlen / buffer size is the only difference
pub fn mgf1_256_2(out: &mut[u8], outlen: usize, input: &[u8])
{
  
  const INLEN: usize = 2 * SPX_N + SPX_SM3_OUTPUT_BYTES;
  let mut inbuf = [0u8; INLEN + 4];
  let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];

  inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

  // While we can fit in at least another full block of SM3 output..
  let mut i = 0;
  let mut idx = 0;
  while (i+1)*SPX_SM3_OUTPUT_BYTES <= outlen {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sm3(&mut out[idx..], &inbuf, INLEN + 4);
    idx += SPX_SM3_OUTPUT_BYTES;
    i += 1;
  }
  // Until we cannot anymore, and we fill the remainder.
  if outlen > i*SPX_SM3_OUTPUT_BYTES {
    u32_to_bytes(&mut inbuf[INLEN..], i as u32);
    sm3(&mut outbuf, &inbuf, INLEN + 4);
    let end = outlen - i*SPX_SM3_OUTPUT_BYTES;
    out[idx..idx+end].copy_from_slice(&outbuf[..end]);
  }
}

// TODO: mfg1 tests instead
#[cfg(test)]
#[cfg(all(feature = "sm3", feature = "f128", feature= "robust"))]
mod tests {
  use super::*;
  #[test]
  fn sm3_finalize() {
    let buf = [0, 46, 130, 247, 82, 182, 99, 36, 30, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 124, 153, 53, 160, 176, 118, 148, 170, 12, 109, 16, 228, 219, 107, 26, 221];
    let mut sm3_state = [20, 22, 52, 101, 4, 22, 68, 118, 244, 194, 114, 161, 208, 242, 205, 126, 223, 57, 106, 139, 71, 255, 239, 55, 65, 254, 4, 118, 170, 37, 3, 106, 0, 0, 0, 0, 0, 0, 0, 64];
    let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];
    let expected = [151, 41, 244, 77, 28, 0, 51, 80, 20, 166, 116, 190, 217, 139, 37, 105, 21, 55, 45, 28, 40, 232, 167, 118, 61, 28, 222, 215, 214, 154, 24, 82];
    sm3_inc_finalize(
      &mut outbuf, &mut sm3_state, &buf, SPX_SM3_ADDR_BYTES + SPX_N
    );
    assert_eq!(outbuf, expected);
  }
}
