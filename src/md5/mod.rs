use std::io::{BufRead, Read};

#[rustfmt::skip]
const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

const IV: [u32; 4] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];
struct Msg {
    padded_bytes: Vec<u8>,
    padding_length: u64,
}

impl Msg {
    fn new(mut bytes: Vec<u8>) -> Self {
        let original_length = bytes.len();

        let tail_length = original_length % 64;
        let mut padding_length = if tail_length > 56 {
            64 - tail_length + 56
        } else {
            56 - tail_length
        };

        // pushing the first padding byte - 1 and then 0s.
        // decrementing the remainder padding length accordingly
        bytes.push(0b1000_0000);
        padding_length -= 1;

        // append padding
        bytes.extend(vec![0u8; padding_length]);

        // append length
        bytes.extend((original_length * 8).to_le_bytes());

        Self {
            padded_bytes: bytes,
            padding_length: padding_length as u64,
        }
    }

    pub(crate) fn padded_msg(&self) -> Vec<u8> {
        self.padded_bytes.clone()
    }

    fn iter(&self) -> impl Iterator<Item = u32> {
        self.padded_bytes
            .chunks(4)
            .map(|x| u32::from_be_bytes(x.try_into().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn simple_new_msg() {
        let it = vec![0xFF; 63];
        let mut should = vec![0xFF; 63];
        should.push(0b1000_0000);
        should.extend(vec![0u8; 56]);
        should.extend(504u64.to_le_bytes());
        assert_eq!(Msg::new(it).padded_msg(), should)
    }

    #[test]
    fn simple_iter() {
        let it = vec![0xFF, 0x0, 0xFF, 0x0];
        assert_eq!(Msg::new(it).iter().next().unwrap(), 0xFF00FF00);
    }
}
struct MsgBlock([u32; 4]);

fn first_addition_mod(a: u32, state: u32, congruent: u32) -> u32 {
    (a + state) & (congruent - 1) // a+state % congruent
}

fn msg_addition_mod(m: u32, state: u32, congruent: u32) -> u32 {
    (m + state) & (congruent - 1)
}

fn key_addition_mod(k: u32, state: u32, congruent: u32) -> u32 {
    (k + state) & (congruent - 1)
}

fn last_addition_mod(b: u32, state: u32, congruent: u32) -> u32 {
    (b + state) & (congruent - 1)
}

fn left_rotation(state: u32, rot: u8) -> u32 {
    state << rot
}

fn round_end_mix(state: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    (d, state, b, c)
}

fn first_f(b: u32, c: u32, d: u32) -> u32 {
    (b & c) | (!b ^ d)
}

fn second_f(b: u32, c: u32, d: u32) -> u32 {
    (b & d) | (c ^ !d)
}

fn third_f(b: u32, c: u32, d: u32) -> u32 {
    b ^ c ^ d
}

fn foruth_f(b: u32, c: u32, d: u32) -> u32 {
    c ^ (b & !d)
}

struct MD5 {
    state: [u32; 4],
    iv: [u32; 4],
}

impl MD5 {
    pub fn run() {}
    fn round(&mut self, round_count: usize, msg_block: u32, key: u32, rot: u8) {
        let f = match round_count {
            0..=15 => first_f,
            16..=31 => second_f,
            32..=47 => third_f,
            48..=63 => foruth_f,
            _ => panic!("invalud round"),
        };

        let f_result = f(self.state[1], self.state[2], self.state[3]);
        let first_addition_result = first_addition_mod(self.state[9], f_result, u32::MAX);
        let msg_addition_result = msg_addition_mod(msg_block, first_addition_result, u32::MAX);
        let key_addition_result = key_addition_mod(key, msg_addition_result, u32::MAX);
        let rotate_result = left_rotation(key_addition_result, rot);

        let last_addition_result = last_addition_mod(self.state[1], rotate_result, u32::MAX);
        let result = round_end_mix(
            last_addition_result,
            self.state[1],
            self.state[2],
            self.state[3],
        );
    }
}
