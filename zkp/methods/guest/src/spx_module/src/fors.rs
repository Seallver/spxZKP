use crate::context::SpxCtx;
use crate::utils::*;
use crate::address::*;
use crate::params::*;
use crate::thash::*;


pub fn fors_sk_to_leaf(
  leaf: &mut[u8], sk: &[u8], ctx: &SpxCtx, fors_leaf_addr: &mut[u32]
)
{
  thash::<1>(leaf, Some(sk), ctx, fors_leaf_addr);
}




/// Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
/// Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
/// Assumes indices has space for SPX_FORS_TREES integers.
pub fn message_to_indices(indices: &mut[u32], m: &[u8])
{
  let mut offset = 0;

  for i in 0..SPX_FORS_TREES  {
    indices[i] = 0;
    for j in 0..SPX_FORS_HEIGHT  {
      indices[i] ^= (((m[offset >> 3] >> (offset & 0x7)) & 0x1) as u32) << j;
      offset += 1;
    }
  }
}

/// Derives the FORS public key from a signature.
/// This can be used for verification by comparing to a known public key, or to
/// subsequently verify a signature on the derived public key. The latter is the
/// typical use-case when used as an FTS below an OTS in a hypertree.
/// Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
pub fn fors_pk_from_sig(
  pk: &mut[u8], sig: &[u8], m: &[u8], ctx: &SpxCtx, fors_addr: &mut[u32]
)
{
  let mut indices = [0u32; SPX_FORS_TREES];
  let mut roots = [0u8; SPX_FORS_TREES * SPX_N];
  let mut leaf = [0u8; SPX_N];
  let mut fors_tree_addr = [0u32; 8];
  let mut fors_pk_addr = [0u32; 8];
  let mut idx_offset;

  copy_keypair_addr(&mut fors_tree_addr, fors_addr);
  copy_keypair_addr(&mut fors_pk_addr, fors_addr);

  set_type(&mut fors_tree_addr, SPX_ADDR_TYPE_FORSTREE);
  set_type(&mut fors_pk_addr, SPX_ADDR_TYPE_FORSPK);

  message_to_indices(&mut indices, m);

  let mut idx = 0usize;
  for i in 0..SPX_FORS_TREES  {
      idx_offset = i as u32 * (1 << SPX_FORS_HEIGHT as u32);

      set_tree_height(&mut fors_tree_addr, 0);
      set_tree_index(&mut fors_tree_addr, indices[i] + idx_offset);

      // Derive the leaf from the included secret key part. 
      fors_sk_to_leaf(&mut leaf, &sig[idx..], ctx, &mut fors_tree_addr);
      idx += SPX_N;

      // Derive the corresponding root node of this tree. 
      compute_root(
        &mut roots[i*SPX_N..], &leaf, indices[i], idx_offset,
        &sig[idx..], SPX_FORS_HEIGHT as u32, ctx, &mut fors_tree_addr
      );
      idx += SPX_N * SPX_FORS_HEIGHT;
  }

  // Hash horizontally across all tree roots to derive the public key. 
  thash::<SPX_FORS_TREES>(pk, Some(&roots), ctx, &fors_pk_addr);
}
