use std::fmt;
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

#[derive(Clone, Copy, Default)]
pub struct BlockState {
    pub left: u32,
    pub right: u32,
}

impl BlockState {
    fn from_u64(input: u64) -> Self {
        Self {
            left: (input >> 32) as u32,
            right: input as u32,
        }
    }

    pub fn to_u64(&self) -> u64 {
        (self.left as u64) << 32 | self.right as u64
    }
}

impl fmt::Debug for BlockState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.to_u64())
    }
}

// DESBuilder as the name suggests, is a builder for the DES struct.
// The reason this is made is in order ot make the stage "function"
// modularity idea clear and in the forefront.
pub struct DESBuilder {
    pc1: Option<Box<dyn Fn(u64) -> LRKey>>,
    rotate_and_pc2: Option<Box<dyn Fn(&mut LRKey, usize) -> u64>>,
    ip: Option<Box<dyn Fn(u64) -> u64>>,
    ip_inv: Option<Box<dyn Fn(u64) -> u64>>,
    key_whitening: Option<Box<dyn Fn(u64, u64) -> u64>>,
    e: Option<Box<dyn Fn(u32) -> u64>>,
    sbox: Option<Box<dyn Fn(u64) -> u32>>,
    p: Option<Box<dyn Fn(u32) -> u32>>,
    state_xor: Option<Box<dyn Fn(u32, u32) -> u32>>,
}

impl Default for DESBuilder {
    fn default() -> Self {
        Self {
            pc1: None,
            rotate_and_pc2: None,
            ip: None,
            ip_inv: None,
            key_whitening: None,
            e: None,
            sbox: None,
            p: None,
            state_xor: None,
        }
    }
}

impl DESBuilder {
    pub fn pc1(mut self, f: impl Fn(u64) -> LRKey + 'static) -> Self {
        self.pc1 = Some(Box::new(f));
        self
    }

    pub fn rotate_and_pc2(mut self, f: impl Fn(&mut LRKey, usize) -> u64 + 'static) -> Self {
        self.rotate_and_pc2 = Some(Box::new(f));
        self
    }

    pub fn ip(mut self, f: impl Fn(u64) -> u64 + 'static) -> Self {
        self.ip = Some(Box::new(f));
        self
    }

    pub fn ip_inv(mut self, f: impl Fn(u64) -> u64 + 'static) -> Self {
        self.ip_inv = Some(Box::new(f));
        self
    }

    pub fn key_whitening(mut self, f: impl Fn(u64, u64) -> u64 + 'static) -> Self {
        self.key_whitening = Some(Box::new(f));
        self
    }

    pub fn e(mut self, f: impl Fn(u32) -> u64 + 'static) -> Self {
        self.e = Some(Box::new(f));
        self
    }

    pub fn sbox(mut self, f: impl Fn(u64) -> u32 + 'static) -> Self {
        self.sbox = Some(Box::new(f));
        self
    }

    pub fn p(mut self, f: impl Fn(u32) -> u32 + 'static) -> Self {
        self.p = Some(Box::new(f));
        self
    }

    pub fn state_xor(mut self, f: impl Fn(u32, u32) -> u32 + 'static) -> Self {
        self.state_xor = Some(Box::new(f));
        self
    }

    pub fn build(self, master_key: u64) -> DES {
        let pc1 = self.pc1.expect("pc1 not configured");
        let current_key = pc1(master_key);
        DES {
            state: BlockState::default(),
            f_state: 0,
            current_round: 0,
            current_key,
            des_stage: DESStage::Start,
            key_stage: KeyStage::MasterKey,
            feistel_stage: FStage::Init,
            rotate_and_pc2: self.rotate_and_pc2.expect("rotate_and_pc2 not configured"),
            ip: self.ip.expect("ip not configured"),
            ip_inv: self.ip_inv.expect("ip_inv not configured"),
            key_whitening: self.key_whitening.expect("key_whitening not configured"),
            e: self.e.expect("e not configured"),
            sbox: self.sbox.expect("sbox not configured"),
            p: self.p.expect("p not configured"),
            state_xor: self.state_xor.expect("state_xor not configured"),
            history: Vec::new(),
        }
    }
}

// DESStage lists the macro stages in a DES cipher - IP -> Rounds -> IP^-1
#[derive(Debug, Clone)]
pub enum DESStage {
    Start,
    InitialPermutation,
    Round,
    FinalPermutation,
}

// FStage lists the intra-F round function stages, there correspond more or less
// to the real DES stages in the round function and to the functions injected
// to DESBuilder.
#[derive(Debug, Clone)]
pub enum FStage {
    Init,
    KeySchedule,
    Expansion,
    KeyWhitening,
    SBox,
    Permutation,
    StateXor,
    Done,
}

// KeyStage lists the stage of the key while going through key-scheduling
#[derive(Debug, Clone)]
pub enum KeyStage {
    MasterKey,
    PC1,
    RotateAndPC2,
}

// DESState is the internal data (state) of the cipher while it is executing.
// The ability to track and extract this infromation is the secret sauce of
// this project.
#[derive(Debug, Clone)]
pub struct DESState {
    pub des_stage: DESStage,
    pub key_stage: KeyStage,
    pub feistel_stage: FStage,
    pub state: BlockState,
    pub f_state: u64,
    pub current_key: LRKey,
}

// DES is essentially the executor of the injected stage functions which also
// collects the history (trace) of the execution.
pub struct DES {
    // state represents the state between rounds
    pub state: BlockState,
    // f_state represents the state inside an fbox each round
    pub f_state: u64,
    current_round: u8,
    current_key: LRKey,
    des_stage: DESStage,
    key_stage: KeyStage,
    feistel_stage: FStage,
    // stage functions to be injected
    rotate_and_pc2: Box<dyn Fn(&mut LRKey, usize) -> u64>,
    ip: Box<dyn Fn(u64) -> u64>,
    ip_inv: Box<dyn Fn(u64) -> u64>,
    key_whitening: Box<dyn Fn(u64, u64) -> u64>,
    e: Box<dyn Fn(u32) -> u64>,
    sbox: Box<dyn Fn(u64) -> u32>,
    p: Box<dyn Fn(u32) -> u32>,
    state_xor: Box<dyn Fn(u32, u32) -> u32>,
    // a full trace of the cipher execution
    history: Vec<DESState>,
}

impl DES {
    fn record(&mut self) {
        self.history.push(DESState {
            des_stage: self.des_stage.clone(),
            key_stage: self.key_stage.clone(),
            feistel_stage: self.feistel_stage.clone(),
            state: self.state,
            f_state: self.f_state,
            current_key: self.current_key,
        });
    }

    pub fn start(&mut self, input: u64) {
        self.history.clear();

        self.des_stage = DESStage::Start;
        self.key_stage = KeyStage::MasterKey;
        self.feistel_stage = FStage::Init;
        self.record();

        let ip_input = (self.ip)(input);
        self.state = BlockState::from_u64(ip_input);

        self.des_stage = DESStage::InitialPermutation;
        self.key_stage = KeyStage::PC1;
        self.record();
    }

    pub fn next_round(&mut self) {
        self.des_stage = DESStage::Round;
        self.key_stage = KeyStage::RotateAndPC2;
        self.feistel_stage = FStage::Init;
        self.f_state = self.state.right as u64;
        self.record();

        let round_key = (self.rotate_and_pc2)(&mut self.current_key, self.current_round.into());

        self.feistel_stage = FStage::KeySchedule;
        self.record();

        self.f_state = (self.e)(self.state.right);
        self.feistel_stage = FStage::Expansion;
        self.record();

        self.f_state = (self.key_whitening)(round_key, self.f_state);
        self.feistel_stage = FStage::KeyWhitening;
        self.record();

        self.f_state = (self.sbox)(self.f_state) as u64;
        self.feistel_stage = FStage::SBox;
        self.record();

        self.f_state = (self.p)(self.f_state as u32) as u64;
        self.feistel_stage = FStage::Permutation;
        self.record();

        self.f_state = (self.state_xor)(self.state.left, self.f_state as u32) as u64;
        self.feistel_stage = FStage::StateXor;
        self.record();

        // feistel swap
        self.state.left = self.state.right;
        self.state.right = self.f_state as u32;

        self.feistel_stage = FStage::Done;
        self.record();

        self.current_round += 1;
    }

    pub fn finalize(&mut self) {
        let preoutput = (self.state.right as u64) << 32 | self.state.left as u64;
        let final_block = (self.ip_inv)(preoutput);
        self.state.left = (final_block >> 32) as u32;
        self.state.right = final_block as u32;

        self.des_stage = DESStage::FinalPermutation;
        self.feistel_stage = FStage::Done;
        self.record();
    }

    pub fn get_state(&self) -> Option<DESState> {
        self.history.last().cloned()
    }

    pub fn get_history(&self) -> &[DESState] {
        &self.history
    }
}
