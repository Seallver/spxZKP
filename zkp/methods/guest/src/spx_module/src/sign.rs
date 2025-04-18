use crate::address::*;
use crate::api::SigError;
use crate::context::SpxCtx;
use crate::fors::*;
use crate::hash::*;
use crate::params::*;
use crate::thash::*;
use crate::utils::*;
use crate::wots::*;

/// Verifies a detached signature and message under a given public key.
pub fn crypto_sign_verify(sig: &[u8], msg: &[u8], pk: &[u8]) -> Result<(), SigError> {
    if sig.len() != SPX_BYTES {
        return Err(SigError::Input);
    }

    let mut ctx = SpxCtx::default();
    let pub_root: &[u8] = &pk[SPX_N..];
    let mut mhash = [0u8; SPX_FORS_MSG_BYTES];
    let mut wots_pk = [0u8; SPX_WOTS_BYTES];
    let (mut root, mut leaf) = ([0u8; SPX_N], [0u8; SPX_N]);
    let mut tree = 0u64;
    let mut idx_leaf = 0u32;
    let (mut wots_addr, mut tree_addr, mut wots_pk_addr) = ([0u32; 8], [0u32; 8], [0u32; 8]);
    let mut idx = 0usize;

    ctx.pub_seed[..].copy_from_slice(&pk[..SPX_N]);

    // This hook allows the hash function instantiation to do whatever
    // preparation or computation it needs, based on the public seed.
    initialize_hash_function(&mut ctx);

    set_type(&mut wots_addr, SPX_ADDR_TYPE_WOTS);
    set_type(&mut tree_addr, SPX_ADDR_TYPE_HASHTREE);
    set_type(&mut wots_pk_addr, SPX_ADDR_TYPE_WOTSPK);

    // Derive the message digest and leaf index from R || PK || M.
    // The additional SPX_N is a result of the hash domain separator.
    hash_message(
        &mut mhash,
        &mut tree,
        &mut idx_leaf,
        sig,
        pk,
        &msg,
        msg.len(),
        &ctx,
    );
    idx += SPX_N;

    // Layer correctly defaults to 0, so no need to set_layer_addr
    set_tree_addr(&mut wots_addr, tree);
    set_keypair_addr(&mut wots_addr, idx_leaf);

    fors_pk_from_sig(&mut root, &sig[idx..], &mhash, &ctx, &mut wots_addr);
    idx += SPX_FORS_BYTES;

    // For each subtree..
    for i in 0..SPX_D {
        set_layer_addr(&mut tree_addr, i as u32);
        set_tree_addr(&mut tree_addr, tree);
        copy_subtree_addr(&mut wots_addr, &mut tree_addr);
        set_keypair_addr(&mut wots_addr, idx_leaf);

        copy_keypair_addr(&mut wots_pk_addr, &mut wots_addr);

        // The WOTS public key is only correct if the signature was correct.
        // Initially, root is the FORS pk, but on subsequent iterations it is
        // the root of the subtree below the currently processed subtree.
        wots_pk_from_sig(&mut wots_pk, &sig[idx..], &root, &ctx, &mut wots_addr);
        idx += SPX_WOTS_BYTES;

        // Compute the leaf node using the WOTS public key.
        thash::<SPX_WOTS_LEN>(&mut leaf, Some(&wots_pk), &ctx, &wots_pk_addr);

        // Compute the root node of this subtree.
        compute_root(
            &mut root,
            &leaf,
            idx_leaf,
            0,
            &sig[idx..],
            SPX_TREE_HEIGHT as u32,
            &ctx,
            &mut tree_addr,
        );
        idx += SPX_TREE_HEIGHT * SPX_N;

        // Update the indices for the next layer.
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree = tree >> SPX_TREE_HEIGHT;
    }

    // Check if the root node equals the root node in the public key.
    if root != pub_root {
        return Err(SigError::Verify);
    }

    return Ok(());
}
