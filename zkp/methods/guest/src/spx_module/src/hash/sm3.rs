#![allow(non_snake_case)]
use crate::context::SpxCtx;
use crate::utils::*;
use crate::params::*;
use crate::sm3::*;

pub fn mgf1_X(out: &mut[u8], outlen: usize, input: &[u8]) {
    mgf1_256_2(out, outlen, input);
}

/// For SM3, there is no immediate reason to initialize at the start,
/// so this function is an empty operation.
pub fn initialize_hash_function(ctx: &mut SpxCtx) { 
  seed_state(ctx);
}

// Computes the message-dependent randomness R, using a secret seed as a key
// for HMAC, and an optional randomization value prefixed to the message.
// This requires m to have at least SPX_SM3_BLOCK_BYTES + SPX_N space
// available in front of the pointer, i.e. before the message to use for the
// prefix. This is necessary to prevent having to move the message around (and
// allocate memory for it).
pub fn gen_message_random(
  r: &mut[u8], sk_prf: &[u8], optrand: &[u8], 
  m: &[u8], mut mlen: usize, _ctx: &SpxCtx
)
{
    let mut buf = [0u8; SPX_SM3_BLOCK_BYTES + SPX_SM3_OUTPUT_BYTES];
    let mut state = [0u8; 8 + SPX_SM3_OUTPUT_BYTES];
    let mut idx = 0; 

    // This implements HMAC-SM3
    for i in 0..SPX_N  {
        buf[i] = 0x36 ^ sk_prf[i];
    }
    buf[SPX_N..SPX_SM3_BLOCK_BYTES].fill(0x36);

    sm3_inc_init(&mut state);
    sm3_inc_blocks(&mut state, &buf, 1);

    buf[..SPX_N].copy_from_slice(&optrand[..SPX_N]);

    // If optrand + message cannot fill up an entire block
    if SPX_N + mlen < SPX_SM3_BLOCK_BYTES {
        buf[SPX_N..SPX_N + mlen].copy_from_slice(&m[..mlen]);
        let tmp_buf = buf.clone();
        sm3_inc_finalize(
          &mut buf[SPX_SM3_BLOCK_BYTES..], &mut state, &tmp_buf, mlen + SPX_N
        );
    }
    // Otherwise first fill a block, so that finalize only uses the message
    else {
        buf[SPX_N..SPX_SM3_BLOCK_BYTES]
          .copy_from_slice(&m[..SPX_SM3_BLOCK_BYTES - SPX_N]);
        sm3_inc_blocks(&mut state, &buf, 1);

        idx += SPX_SM3_BLOCK_BYTES - SPX_N;
        mlen -= SPX_SM3_BLOCK_BYTES - SPX_N;
        sm3_inc_finalize(
          &mut buf[SPX_SM3_BLOCK_BYTES..], &mut state, &m[idx..], mlen
        );
    }

    for i in 0..SPX_N  {
        buf[i] = 0x5c ^ sk_prf[i];
    }
    buf[SPX_N..SPX_SM3_BLOCK_BYTES].fill(0x5c);
    let tmp_buf = buf.clone();
    sm3(&mut buf, &tmp_buf, SPX_SM3_BLOCK_BYTES + SPX_SM3_OUTPUT_BYTES);
    r[..SPX_N].copy_from_slice(&buf[..SPX_N]);
}


/// Computes the message hash using R, the public key, and the message.
/// Outputs the message digest and the index of the leaf. The index is split in
/// the tree index and the leaf index, for convenient copying to an address.
pub fn hash_message(
  digest: &mut[u8], tree: &mut u64, leaf_idx: &mut u32, R: &[u8], pk: &[u8], 
  m: &[u8], mut mlen: usize, _ctx: &SpxCtx
)
{
  let mut seed = [0u8; 2*SPX_N + SPX_SM3_OUTPUT_BYTES];

  /// Round to nearest multiple of SPX_SM3_BLOCK_BYTES
  // TODO: cleanup this monstrosity
  const SPX_INBLOCKS: usize = (((SPX_N + SPX_PK_BYTES + SPX_SM3_BLOCK_BYTES - 1) as isize &
  -(SPX_SM3_BLOCK_BYTES as isize)) / SPX_SM3_BLOCK_BYTES as isize) as usize;
  
  let mut inbuf = [0u8; SPX_INBLOCKS * SPX_SM3_BLOCK_BYTES];

  let mut buf = [0u8; SPX_DGST_BYTES];
  let mut state = [0u8; 8 + SPX_SM3_OUTPUT_BYTES];
  let mut buf_idx = 0;
  let mut m_idx = 0;
  
  sm3_inc_init(&mut state);

  // seed: SM3(R ‖ PK.seed ‖ PK.root ‖ M)
  inbuf[..SPX_N].copy_from_slice(&R[..SPX_N]);
  inbuf[SPX_N..SPX_N + SPX_PK_BYTES].copy_from_slice(&pk[..SPX_PK_BYTES]);

  // If R + pk + message cannot fill up an entire block
  const START: usize = SPX_N + SPX_PK_BYTES; 
  if START + mlen < SPX_INBLOCKS * SPX_SM3_BLOCK_BYTES {
    inbuf[START..START + mlen].copy_from_slice(&m[..mlen]);
    sm3_inc_finalize(
      &mut seed[2*SPX_N..], &mut state, &inbuf, SPX_N + SPX_PK_BYTES + mlen
    );
  }
  // Otherwise first fill a block, so that finalize only uses the message
  else {
    const END: usize = SPX_INBLOCKS * SPX_SM3_BLOCK_BYTES - SPX_N - SPX_PK_BYTES;
    inbuf[START..START+END].copy_from_slice(&m[..END]);
    sm3_inc_blocks(&mut state, &inbuf, SPX_INBLOCKS);

    m_idx += END;
    mlen -= END;
    sm3_inc_finalize(&mut seed[2*SPX_N..], &mut state, &m[m_idx..], mlen);
  }

  // H_msg: MGF1-SM3(R ‖ PK.seed ‖ seed)
  seed[..SPX_N].copy_from_slice(&R[..SPX_N]);
  seed[SPX_N..SPX_N*2].copy_from_slice(&pk[..SPX_N]);

  // By doing this in two steps, we prevent hashing the message twice;
  // otherwise each iteration in MGF1 would hash the message again.
  
  mgf1_X(&mut buf, SPX_DGST_BYTES, &seed);  

  digest[..SPX_FORS_MSG_BYTES].copy_from_slice(&buf[..SPX_FORS_MSG_BYTES]);
  buf_idx += SPX_FORS_MSG_BYTES;

  *tree = bytes_to_ull(&buf[buf_idx..], SPX_TREE_BYTES);
  *tree &= !0u64 >> (64 - SPX_TREE_BITS);
  buf_idx += SPX_TREE_BYTES;

  *leaf_idx = bytes_to_ull(&buf[buf_idx..], SPX_LEAF_BYTES) as u32;
  *leaf_idx &= !0u32 >> (32 - SPX_LEAF_BITS);
}


