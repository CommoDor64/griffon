pub mod aes;
pub mod des;
pub use des::nist_des::canonical_builder;
pub use des::{BlockState, DES, DESBuilder, DESStage, DESState, FStage, KeyStage, LRKey};

use std::cmp::min;
use std::ops::{Shl, Shr};
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
        let mut leftover_bits = rhs%N;

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
        let mut leftover_bits = rhs%N;

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
        is = is << 128+8;
        let should = vec![0x23_4567_89AB_CDEF_00, 0x23_4567_89AB_CDEF_01u64];
        assert_eq!(is.0, should);
    }

    #[test]
    fn test_multi_round_shr() {
        let mut is: BitVector<128> = BitVector::new();
        is.add(&[0x0123_4567_89AB_CDEF, 0x0123_4567_89AB_CDEF]);
        is = is >> 128+8;
        let should = vec![0xEF_0123_4567_89AB_CD, 0x000123_4567_89AB_CDu64];
        assert_eq!(is.0, should);
    }

}
