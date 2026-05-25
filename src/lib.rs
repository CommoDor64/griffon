pub mod aes;
pub mod des;
pub mod md5;
pub use des::nist_des::canonical_builder;
pub use des::{BlockState, DES, DESBuilder, DESStage, DESState, FStage, KeyStage, LRKey};

use std::cmp::min;

// BitVector allows for arbitrary sized structs of size ceil(N/64).
// There are two good use cases for it in the scope of griffon -
// 1. Arbitrary length keys and states - NIST DES master key is of size 56bit,
// the round key is 48bit, and state before expansion is 32 , and 48 after.
// This means that we need specialized types to clearly state the intent by a proper
// type.
// 2. Allow for larger than 128bit keys, states etc.
//
// Internally, it essentially "big-endian", where the first element (element 0) is the first unsigned 64bit segment of
// the vector, and the second is the second. For exmaple:
//
// BitVector<128> = [0x01234567_89ABCDEF, 0x11111111_11111111]
// and if coverted to u128, it will look about
// to_u128(BitVector<128>) = 0x11111111_11111111_01234567_89ABCDEF
//
// One downside to this, is that it doesnt use any vector operation (e.g AMD AVX-x) and therefore slow.
// Luckily this project is putting effort on being readable and optimiziations are done only when relevant.
pub(crate) struct BitVector<const N: usize>(Vec<u64>);

impl<const N: usize> BitVector<N> {
    pub(crate) fn new() -> Self {
        BitVector(Vec::with_capacity(N.div_ceil(64)))
    }

    pub(crate) fn add(&mut self, key: &[u64]) {
        for k in key {
            self.0.push(*k);
        }
    }

    pub(crate) fn shl(mut self, rhs: usize) -> Self {
        let mut leftover_bits = rhs % N;

        while leftover_bits > 0 {
            let mut prev_leftover = 0u64;
            let shl_bitcount = min(64, leftover_bits);
            for w in &mut self.0 {
                let tmp = *w;
                prev_leftover >>= 64 - shl_bitcount;
                *w = (*w << shl_bitcount) | prev_leftover;
                prev_leftover = tmp;
            }

            leftover_bits -= shl_bitcount;
        }

        self
    }

    pub(crate) fn shr(mut self, rhs: usize) -> Self {
        let mut leftover_bits = rhs % N;

        while leftover_bits > 0 {
            let mut prev_leftover = 0u64;
            let shr_bitcount = min(64, leftover_bits);
            for w in self.0.iter_mut().rev() {
                let tmp = *w;
                prev_leftover <<= 64 - shr_bitcount;
                *w = (*w >> shr_bitcount) | prev_leftover;
                prev_leftover = tmp;
            }

            leftover_bits -= shr_bitcount;
        }

        self
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    #[test]
    fn test_simple_shl() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is.shl(8);
        let should = vec![0x23_4567_89AB_CDEF_00, 0x23_4567_89AB_CDEF_01u64];
        assert_eq!(is.0, should);
    }

    #[test]
    fn test_simple_shr() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is.shr(8);
        let should = vec![0xEF_0123_4567_89AB_CD, 0x000123_4567_89AB_CDu64];
        assert_eq!(is.0, should);
    }

    #[test]
    fn test_multi_round_shl() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is.shl(128 + 8);
        let should = vec![0x23_4567_89AB_CDEF_00, 0x23_4567_89AB_CDEF_01u64];
        assert_eq!(is.0, should);
    }

    #[test]
    fn test_multi_round_shr() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is.shr(128 + 8);
        let should = vec![0xEF_0123_4567_89AB_CD, 0x000123_4567_89AB_CDu64];
        assert_eq!(is.0, should);
    }
}
