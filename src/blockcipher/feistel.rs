use std::rc::Rc;

#[derive(Clone, Copy, Debug)]
pub struct FStepTrace<B: Copy, E: Copy> {
    pub after_expand:   E,
    pub after_key_mix:  E,
    pub after_substitute: B,
    pub after_permute:  B,
}

#[derive(Clone, Copy, Debug)]
pub struct FeistelRoundState<B: Copy, E: Copy> {
    pub round:     usize,
    pub left:      B,
    pub right:     B,
    pub round_key: E,
    pub f_trace:   FStepTrace<B, E>,
}

pub struct FeistelF<B: Copy, E: Copy> {
    expand:   Box<dyn Fn(B) -> E>,
    key_mix:  Box<dyn Fn(E, E) -> E>,
    substitute: Box<dyn Fn(E) -> B>,
    permute:  Box<dyn Fn(B) -> B>,
}

impl<B: Copy, E: Copy> FeistelF<B, E> {
    pub fn call(&self, block: B, round_key: E) -> (B, FStepTrace<B, E>) {
        let expanded   = (self.expand)(block);
        let mixed      = (self.key_mix)(expanded, round_key);
        let substituteed = (self.substitute)(mixed);
        let permuted   = (self.permute)(substituteed);
        (
            permuted,
            FStepTrace {
                after_expand:   expanded,
                after_key_mix:  mixed,
                after_substitute: substituteed,
                after_permute:  permuted,
            },
        )
    }
}

pub struct FeistelFBuilder<B: Copy, E: Copy> {
    expand:   Option<Box<dyn Fn(B) -> E>>,
    key_mix:  Option<Box<dyn Fn(E, E) -> E>>,
    substitute: Option<Box<dyn Fn(E) -> B>>,
    permute:  Option<Box<dyn Fn(B) -> B>>,
}

impl<B: Copy + 'static, E: Copy + 'static> FeistelFBuilder<B, E> {
    pub fn new() -> Self {
        Self { expand: None, key_mix: None, substitute: None, permute: None }
    }

    pub fn expand(mut self, f: impl Fn(B) -> E + 'static) -> Self {
        self.expand = Some(Box::new(f));
        self
    }

    pub fn key_mix(mut self, f: impl Fn(E, E) -> E + 'static) -> Self {
        self.key_mix = Some(Box::new(f));
        self
    }

    pub fn substitute(mut self, f: impl Fn(E) -> B + 'static) -> Self {
        self.substitute = Some(Box::new(f));
        self
    }

    pub fn permute(mut self, f: impl Fn(B) -> B + 'static) -> Self {
        self.permute = Some(Box::new(f));
        self
    }

    pub fn build(self) -> FeistelF<B, E> {
        FeistelF {
            expand:   self.expand.expect("expand not configured"),
            key_mix:  self.key_mix.expect("key_mix not configured"),
            substitute: self.substitute.expect("substitute not configured"),
            permute:  self.permute.expect("permute not configured"),
        }
    }
}

pub struct KeySchedule<MK: Copy, RK: Copy> {
    // S (internal state) is erased inside the closure.
    make_iter: Rc<dyn Fn(MK) -> Box<dyn FnMut() -> RK>>,
}

impl<MK: Copy, RK: Copy> KeySchedule<MK, RK> {
    pub fn for_key(&self, master_key: MK) -> Box<dyn FnMut() -> RK> {
        (self.make_iter)(master_key)
    }
}

pub struct KeyScheduleBuilder<MK, S, RK> {
    init: Option<Box<dyn Fn(MK) -> S>>,
    step: Option<Box<dyn Fn(&mut S, usize) -> RK>>,
}

impl<MK: Copy + 'static, S: 'static, RK: Copy + 'static> KeyScheduleBuilder<MK, S, RK> {
    pub fn new() -> Self {
        Self { init: None, step: None }
    }

    pub fn init(mut self, f: impl Fn(MK) -> S + 'static) -> Self {
        self.init = Some(Box::new(f));
        self
    }

    pub fn step(mut self, f: impl Fn(&mut S, usize) -> RK + 'static) -> Self {
        self.step = Some(Box::new(f));
        self
    }

    pub fn build(self) -> KeySchedule<MK, RK> {
        let init = self.init.expect("init not configured");
        let step = Rc::new(self.step.expect("step not configured"));
        KeySchedule {
            make_iter: Rc::new(move |mk| {
                let mut state = init(mk);
                let step      = Rc::clone(&step);
                let mut round = 0usize;
                Box::new(move || {
                    let rk = step(&mut state, round);
                    round += 1;
                    rk
                })
            }),
        }
    }
}

pub struct Feistel<B: Copy, E: Copy> {
    xor:     Box<dyn Fn(B, B) -> B>,
    f:       FeistelF<B, E>,
    rounds:  usize,
    history: Vec<FeistelRoundState<B, E>>,
}

impl<B: Copy, E: Copy> Feistel<B, E> {
    pub fn run(
        &mut self,
        left: B,
        right: B,
        key_schedule: &mut dyn FnMut() -> E,
    ) -> (B, B) {
        self.history.clear();
        let mut l = left;
        let mut r = right;
        for round in 0..self.rounds {
            let round_key        = key_schedule();
            let (f_out, f_trace) = self.f.call(r, round_key);
            let new_r            = (self.xor)(l, f_out);
            self.history.push(FeistelRoundState { round, left: l, right: r, round_key, f_trace });
            l = r;
            r = new_r;
        }
        (l, r)
    }

    pub fn get_history(&self) -> &[FeistelRoundState<B, E>] {
        &self.history
    }
}

pub struct FeistelBuilder<B: Copy, E: Copy> {
    xor:    Option<Box<dyn Fn(B, B) -> B>>,
    f:      Option<FeistelF<B, E>>,
    rounds: usize,
}

impl<B: Copy + 'static, E: Copy + 'static> FeistelBuilder<B, E> {
    pub fn new() -> Self {
        Self { xor: None, f: None, rounds: 16 }
    }

    pub fn xor(mut self, f: impl Fn(B, B) -> B + 'static) -> Self {
        self.xor = Some(Box::new(f));
        self
    }

    pub fn f(mut self, f: FeistelF<B, E>) -> Self {
        self.f = Some(f);
        self
    }

    pub fn rounds(mut self, n: usize) -> Self {
        self.rounds = n;
        self
    }

    pub fn build(self) -> Feistel<B, E> {
        Feistel {
            xor:     self.xor.expect("xor not configured"),
            f:       self.f.expect("f not configured"),
            rounds:  self.rounds,
            history: Vec::new(),
        }
    }
}
