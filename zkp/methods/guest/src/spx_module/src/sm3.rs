use crate::context::SpxCtx;
use crate::params::*;
use crate::utils::*;
use core::convert::TryInto;

pub const SPX_SM3_BLOCK_BYTES: usize = 64;
pub const SPX_SM3_OUTPUT_BYTES: usize = 32; /* This does not necessarily equal SPX_N */

pub const SPX_SM3_ADDR_BYTES: usize = 22;

const IV_256: [u8; 32] = [
    0x73, 0x80, 0x16, 0x6F, //A
    0x49, 0x14, 0xB2, 0xB9, //B
    0x17, 0x24, 0x42, 0xD7, //C
    0xDA, 0x8A, 0x06, 0x00, //D
    0xA9, 0x6F, 0x30, 0xBC, //E
    0x16, 0x31, 0x38, 0xAA, //F
    0xE3, 0x8D, 0xEE, 0x4D, //G
    0xB0, 0xFB, 0x0E, 0x4E, //H
];

pub fn load_bigendian_32(x: &[u8]) -> u32 {
    u32::from_be_bytes(x[..4].try_into().unwrap())
}

pub fn load_bigendian_64(x: &[u8]) -> u64 {
    u64::from_be_bytes(x[..8].try_into().unwrap())
}

pub fn store_bigendian_32(x: &mut [u8], u: u32) {
    x[..4].copy_from_slice(&u.to_be_bytes());
}

pub fn store_bigendian_64(x: &mut [u8], u: u64) {
    x[..8].copy_from_slice(&u.to_be_bytes());
}

#[inline]
fn rotl(x: u32, n: i32) -> u32 {
    x.rotate_left(n as u32)
}

#[inline]
#[allow(non_snake_case)]
fn P0(x: u32) -> u32 {
    x ^ rotl(x, 9) ^ rotl(x, 17)
}

#[inline]
#[allow(non_snake_case)]
fn P1(x: u32) -> u32 {
    x ^ rotl(x, 15) ^ rotl(x, 23)
}

#[inline]
#[allow(non_snake_case)]
fn FF(x: u32, y: u32, z: u32, j: i32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | (x & z) | (y & z)
    }
}

#[inline]
#[allow(non_snake_case)]
fn GG(x: u32, y: u32, z: u32, j: i32) -> u32 {
    if j < 16 {
        x ^ y ^ z
    } else {
        (x & y) | ((!x) & z)
    }
}

#[inline]
#[allow(non_snake_case)]
fn T(j: i32) -> u32 {
    if j < 16 {
        0x79cc4519
    } else {
        0x7a879d8a
    }
}

// 分块哈希
#[allow(non_snake_case)]
pub fn crypto_hashblocks_sm3(statebytes: &mut [u8], mut input: &[u8]) {
    let mut state = [0u32; 8];

    let mut a = load_bigendian_32(&statebytes[0..4]);
    state[0] = a;
    let mut b = load_bigendian_32(&statebytes[4..8]);
    state[1] = b;
    let mut c = load_bigendian_32(&statebytes[8..12]);
    state[2] = c;
    let mut d = load_bigendian_32(&statebytes[12..16]);
    state[3] = d;
    let mut e = load_bigendian_32(&statebytes[16..20]);
    state[4] = e;
    let mut f = load_bigendian_32(&statebytes[20..24]);
    state[5] = f;
    let mut g = load_bigendian_32(&statebytes[24..28]);
    state[6] = g;
    let mut h = load_bigendian_32(&statebytes[28..32]);
    state[7] = h;

    let mut w = [0u32; 68];
    let mut W = [0u32; 64];

    while input.len() >= 64 {
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for i in 0..16 {
            w[i] = load_bigendian_32(&input[i * 4..(i + 1) * 4]);
        }
        for i in 16..68 {
            w[i] = P1(w[i - 16] ^ w[i - 9] ^ rotl(w[i - 3], 15)) ^ rotl(w[i - 13], 7) ^ w[i - 6];
        }
        for i in 0..64 {
            W[i] = w[i] ^ w[i + 4];
        }

        for j in 0..64 {
            let SS1 = rotl(rotl(a, 12).wrapping_add(e).wrapping_add(rotl(T(j), j)), 7);
            let SS2 = SS1 ^ rotl(a, 12);
            let TT1 = FF(a, b, c, j)
                .wrapping_add(d)
                .wrapping_add(SS2)
                .wrapping_add(W[j as usize]);
            let TT2 = GG(e, f, g, j)
                .wrapping_add(h)
                .wrapping_add(SS1)
                .wrapping_add(w[j as usize]);
            d = c;
            c = rotl(b, 9);
            b = a;
            a = TT1;
            h = g;
            g = rotl(f, 19);
            f = e;
            e = P0(TT2);
        }

        state[0] ^= a;
        state[1] ^= b;
        state[2] ^= c;
        state[3] ^= d;
        state[4] ^= e;
        state[5] ^= f;
        state[6] ^= g;
        state[7] ^= h;

        input = &input[64..];
    }

    store_bigendian_32(&mut statebytes[0..4], state[0]);
    store_bigendian_32(&mut statebytes[4..8], state[1]);
    store_bigendian_32(&mut statebytes[8..12], state[2]);
    store_bigendian_32(&mut statebytes[12..16], state[3]);
    store_bigendian_32(&mut statebytes[16..20], state[4]);
    store_bigendian_32(&mut statebytes[20..24], state[5]);
    store_bigendian_32(&mut statebytes[24..28], state[6]);
    store_bigendian_32(&mut statebytes[28..32], state[7]);
}

pub fn sm3_inc_init(state: &mut [u8]) {
    // state 前 32 字节存哈希结果，后 8 字节存已处理的消息的长度
    for i in 0..32 {
        state[i] = IV_256[i];
    }
    for i in 32..40 {
        state[i] = 0;
    }
}

pub fn sm3_inc_blocks(state: &mut [u8], input: &[u8], inblocks: usize) {
    let mut bytes = load_bigendian_64(&state[32..40]);

    crypto_hashblocks_sm3(state, &input[..64 * inblocks]);
    bytes += (64 * inblocks) as u64;

    store_bigendian_64(&mut state[32..40], bytes);
}

pub fn sm3_inc_finalize(out: &mut [u8], state: &mut [u8], input: &[u8], inlen: usize) {
    let mut padded = [0u8; 128];
    let bytes = load_bigendian_64(&state[32..40]) + inlen as u64;

    // 先对能满足512比特分组的数据做哈希
    crypto_hashblocks_sm3(state, &input[..inlen & !63]);

    // 计算剩余长度和数据起始地址
    let rem_len = inlen & 63;
    let rem_input = &input[(inlen - rem_len)..inlen];

    // 复制剩余数据到填充区
    padded[..rem_len].copy_from_slice(rem_input);
    // 填充开始时先填一个 0x80
    padded[rem_len] = 0x80;

    if rem_len < 56 {
        for i in rem_len + 1..56 {
            padded[i] = 0;
        }
        padded[56] = (bytes >> 53) as u8;
        padded[57] = (bytes >> 45) as u8;
        padded[58] = (bytes >> 37) as u8;
        padded[59] = (bytes >> 29) as u8;
        padded[60] = (bytes >> 21) as u8;
        padded[61] = (bytes >> 13) as u8;
        padded[62] = (bytes >> 5) as u8;
        padded[63] = (bytes << 3) as u8;
        crypto_hashblocks_sm3(state, &padded[..64]);
    } else {
        for i in rem_len + 1..120 {
            padded[i] = 0;
        }
        padded[120] = (bytes >> 53) as u8;
        padded[121] = (bytes >> 45) as u8;
        padded[122] = (bytes >> 37) as u8;
        padded[123] = (bytes >> 29) as u8;
        padded[124] = (bytes >> 21) as u8;
        padded[125] = (bytes >> 13) as u8;
        padded[126] = (bytes >> 5) as u8;
        padded[127] = (bytes << 3) as u8;
        crypto_hashblocks_sm3(state, &padded);
    }

    // 输出最终结果
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
pub fn mgf1_256(out: &mut [u8], outlen: usize, input: &[u8]) {
    const INLEN: usize = SPX_N + SPX_SM3_ADDR_BYTES;
    let mut inbuf = [0u8; INLEN + 4];
    let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];

    inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

    // While we can fit in at least another full block of SM3 output..
    let mut i = 0;
    let mut idx = 0;
    while (i + 1) * SPX_SM3_OUTPUT_BYTES <= outlen {
        u32_to_bytes(&mut inbuf[INLEN..], i as u32);
        sm3(&mut out[idx..], &inbuf, INLEN + 4);
        idx += SPX_SM3_OUTPUT_BYTES;
        i += 1;
    }
    // Until we cannot anymore, and we fill the remainder.
    if outlen > i * SPX_SM3_OUTPUT_BYTES {
        u32_to_bytes(&mut inbuf[INLEN..], i as u32);
        sm3(&mut outbuf, &inbuf, INLEN + 4);
        let end = outlen - i * SPX_SM3_OUTPUT_BYTES;
        out[idx..idx + end].copy_from_slice(&outbuf[..end]);
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
pub fn mgf1_256_2(out: &mut [u8], outlen: usize, input: &[u8]) {
    const INLEN: usize = 2 * SPX_N + SPX_SM3_OUTPUT_BYTES;
    let mut inbuf = [0u8; INLEN + 4];
    let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];

    inbuf[..INLEN].copy_from_slice(&input[..INLEN]);

    // While we can fit in at least another full block of SM3 output..
    let mut i = 0;
    let mut idx = 0;
    while (i + 1) * SPX_SM3_OUTPUT_BYTES <= outlen {
        u32_to_bytes(&mut inbuf[INLEN..], i as u32);
        sm3(&mut out[idx..], &inbuf, INLEN + 4);
        idx += SPX_SM3_OUTPUT_BYTES;
        i += 1;
    }
    // Until we cannot anymore, and we fill the remainder.
    if outlen > i * SPX_SM3_OUTPUT_BYTES {
        u32_to_bytes(&mut inbuf[INLEN..], i as u32);
        sm3(&mut outbuf, &inbuf, INLEN + 4);
        let end = outlen - i * SPX_SM3_OUTPUT_BYTES;
        out[idx..idx + end].copy_from_slice(&outbuf[..end]);
    }
}

// TODO: mfg1 tests instead
#[cfg(test)]
#[cfg(all(feature = "sm3", feature = "f128", feature = "robust"))]
mod tests {
    use super::*;
    #[test]
    fn sm3_finalize() {
        let buf = [
            0, 46, 130, 247, 82, 182, 99, 36, 30, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 4, 124, 153,
            53, 160, 176, 118, 148, 170, 12, 109, 16, 228, 219, 107, 26, 221,
        ];
        let mut sm3_state = [
            20, 22, 52, 101, 4, 22, 68, 118, 244, 194, 114, 161, 208, 242, 205, 126, 223, 57, 106,
            139, 71, 255, 239, 55, 65, 254, 4, 118, 170, 37, 3, 106, 0, 0, 0, 0, 0, 0, 0, 64,
        ];
        let mut outbuf = [0u8; SPX_SM3_OUTPUT_BYTES];
        let expected = [
            151, 41, 244, 77, 28, 0, 51, 80, 20, 166, 116, 190, 217, 139, 37, 105, 21, 55, 45, 28,
            40, 232, 167, 118, 61, 28, 222, 215, 214, 154, 24, 82,
        ];
        sm3_inc_finalize(
            &mut outbuf,
            &mut sm3_state,
            &buf,
            SPX_SM3_ADDR_BYTES + SPX_N,
        );
        assert_eq!(outbuf, expected);
    }
}
