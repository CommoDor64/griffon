use std::fmt;

use crate::blockcipher::{Feistel, FeistelBuilder, FeistelF, FeistelRoundState, KeySchedule};

pub mod nist_des;

#[derive(Clone, Copy)]
pub struct LRKey {
    pub left: u32,
    pub right: u32,
}

impl LRKey {
    pub fn to_u64(&self) -> u64 {
        (self.left as u64) << 28 | self.right as u64
    }

    pub fn from_u64(input: u64) -> Self {
        Self {
            left: (input >> 28) as u32,
            right: input as u32,
        }
    }
}

impl fmt::Debug for LRKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LRKey {{ left: 0x{:07x}, right: 0x{:07x} }}",
            self.left, self.right
        )
    }
}

#[derive(Clone, Debug)]
pub enum DESTraceEntry {
    /// Initial permutation step.
    IP { input: u64, output: u64 },
    /// One Feistel round (contains full F sub-step trace).
    Round(FeistelRoundState<u32, u64>),
    /// Final permutation step.
    FP { input: u64, output: u64 },
}

pub type DESTrace = Vec<DESTraceEntry>;

pub struct DESBuilder {
    ip: Option<Box<dyn Fn(u64) -> u64>>,
    ip_inv: Option<Box<dyn Fn(u64) -> u64>>,
    split: Option<Box<dyn Fn(u64) -> (u32, u32)>>,
    combine: Option<Box<dyn Fn(u32, u32) -> u64>>,
    key_schedule: Option<KeySchedule<u64, u64>>,
    f: Option<FeistelF<u32, u64>>,
    rounds: usize,
}

impl DESBuilder {
    pub fn new() -> Self {
        Self {
            ip: None,
            ip_inv: None,
            split: None,
            combine: None,
            key_schedule: None,
            f: None,
            rounds: 16,
        }
    }

    pub fn ip(mut self, f: impl Fn(u64) -> u64 + 'static) -> Self {
        self.ip = Some(Box::new(f));
        self
    }

    pub fn ip_inv(mut self, f: impl Fn(u64) -> u64 + 'static) -> Self {
        self.ip_inv = Some(Box::new(f));
        self
    }

    pub fn split(mut self, f: impl Fn(u64) -> (u32, u32) + 'static) -> Self {
        self.split = Some(Box::new(f));
        self
    }

    pub fn combine(mut self, f: impl Fn(u32, u32) -> u64 + 'static) -> Self {
        self.combine = Some(Box::new(f));
        self
    }

    pub fn key_schedule(mut self, ks: KeySchedule<u64, u64>) -> Self {
        self.key_schedule = Some(ks);
        self
    }

    pub fn f(mut self, f: FeistelF<u32, u64>) -> Self {
        self.f = Some(f);
        self
    }

    pub fn rounds(mut self, n: usize) -> Self {
        self.rounds = n;
        self
    }

    pub fn build(self, master_key: u64) -> DES {
        let feistel = FeistelBuilder::new()
            .xor(|l: u32, r: u32| l ^ r)
            .f(self.f.expect("f not configured"))
            .rounds(self.rounds)
            .build();

        DES {
            ip: self.ip.expect("ip not configured"),
            ip_inv: self.ip_inv.expect("ip_inv not configured"),
            split: self.split.expect("split not configured"),
            combine: self.combine.expect("combine not configured"),
            key_schedule: self.key_schedule.expect("key_schedule not configured"),
            master_key,
            feistel,
        }
    }
}

pub struct DES {
    ip: Box<dyn Fn(u64) -> u64>,
    ip_inv: Box<dyn Fn(u64) -> u64>,
    split: Box<dyn Fn(u64) -> (u32, u32)>,
    combine: Box<dyn Fn(u32, u32) -> u64>,
    key_schedule: KeySchedule<u64, u64>,
    master_key: u64,
    feistel: Feistel<u32, u64>,
}

impl DES {
    pub fn encrypt(&mut self, plaintext: u64) -> (u64, DESTrace) {
        let ip_out = (self.ip)(plaintext);
        let (l0, r0) = (self.split)(ip_out);
        let mut key_iter = self.key_schedule.for_key(self.master_key);
        let (l_out, r_out) = self.feistel.run(l0, r0, &mut *key_iter);
        let rounds: Vec<_> = self.feistel.get_history().to_vec();
        let fp_in = (self.combine)(l_out, r_out);
        let ciphertext = (self.ip_inv)(fp_in);

        let mut trace = Vec::with_capacity(rounds.len() + 2);
        trace.push(DESTraceEntry::IP {
            input: plaintext,
            output: ip_out,
        });
        trace.extend(rounds.into_iter().map(DESTraceEntry::Round));
        trace.push(DESTraceEntry::FP {
            input: fp_in,
            output: ciphertext,
        });

        (ciphertext, trace)
    }
}
