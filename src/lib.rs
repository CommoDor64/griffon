pub mod aes;
pub mod des;
pub use des::nist_des::canonical_builder;
pub use des::{BlockState, DES, DESBuilder, DESStage, DESState, FStage, KeyStage, LRKey};

use std::cmp::min;
use std::ops::{Shl, Shr};

// BitVector allows for arbitrary sized structs of size ceil(N/64).
// There are two good use cases for it in the scope of griffon - 
// 1. Arbitrary length keys and states - NIST DES master key is of size 58bit,
// the round key is 46bit, and state before expansion is 32 , and 48 after.
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
        BitVector(Vec::with_capacity((N + 63) / 64))
    }

    pub(crate) fn add(&mut self, key: &[u64]) {
        for k in key {
            self.0.push(*k);
        }
    }
}

impl<const N: usize> Shl<usize> for BitVector<N> {
    type Output = Self;

    fn shl(mut self, rhs: usize) -> Self::Output {
        let mut leftover_bits = rhs % N;

        while leftover_bits > 0 {
            let mut prev_leftover = 0u64;
            let shl_bitcount = min(64, leftover_bits);
            for w in self.0.iter_mut() {
                let tmp1 = *w;
                *w <<= shl_bitcount;
                prev_leftover >>= 64 - shl_bitcount;
                *w |= prev_leftover;
                prev_leftover = tmp1;
            }

            leftover_bits -= shl_bitcount;
        }

        self
    }
}

impl<const N: usize> Shr<usize> for BitVector<N> {
    type Output = Self;

    fn shr(mut self, rhs: usize) -> Self::Output {
        let mut leftover_bits = rhs % N;

        while leftover_bits > 0 {
            let mut prev_leftover = 0u64;
            let shr_bitcount = min(64, leftover_bits);
            for w in self.0.iter_mut().rev() {
                let tmp1 = *w;
                *w >>= shr_bitcount;
                prev_leftover <<= 64 - shr_bitcount;
                *w |= prev_leftover;
                prev_leftover = tmp1;
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
        is = is << 8;
        let should = vec![0x23_4567_89AB_CDEF_00, 0x23_4567_89AB_CDEF_01u64];
        assert_eq!(is.0, should);
    }

    #[test]
    fn test_simple_shr() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is >> 8;
        let should = vec![0xEF_0123_4567_89AB_CD, 0x000123_4567_89AB_CDu64];
        assert_eq!(is.0, should);
    }

    #[test]
    fn test_multi_round_shl() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is << 128 + 8;
        let should = vec![0x23_4567_89AB_CDEF_00, 0x23_4567_89AB_CDEF_01u64];
        assert_eq!(is.0, should);
    }

    #[test]
    fn test_multi_round_shr() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is >> 128 + 8;
        let should = vec![0xEF_0123_4567_89AB_CD, 0x000123_4567_89AB_CDu64];
        assert_eq!(is.0, should);
    }
}
