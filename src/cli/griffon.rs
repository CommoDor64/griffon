use griffon::{canonical_builder, DESStage, DESState, FStage};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    crossterm::{
        event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
        execute,
        terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    },
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
};

struct App {
    trace: Vec<DESState>,
    cursor: usize,
}

impl App {
    fn new(trace: Vec<DESState>) -> Self {
        Self { trace, cursor: 0 }
    }

    fn prev(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    fn next(&mut self) {
        if self.cursor + 1 < self.trace.len() {
            self.cursor += 1;
        }
    }

    fn stage_label(&self) -> String {
        match &self.trace[self.cursor].des_stage {
            DESStage::Start => "Start".to_string(),
            DESStage::InitialPermutation => "Initial Permutation".to_string(),
            DESStage::Round => {
                let r = self.cursor.saturating_sub(2) / 8 + 1;
                format!("Round {r}")
            }
            DESStage::FinalPermutation => "Final Permutation".to_string(),
        }
    }
}

struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    }
}

fn parse_hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .unwrap_or_else(|e| {
            eprintln!("Invalid hex '{s}': {e}");
            std::process::exit(1);
        })
}

fn ln(text: &'static str, hl: bool) -> Line<'static> {
    if hl {
        Line::from(Span::styled(
            text,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(text)
    }
}

fn ip_sketch(stage: &DESStage) -> Vec<Line<'static>> {
    let start = matches!(stage, DESStage::Start);
    let ip = matches!(stage, DESStage::InitialPermutation);
    let fp = matches!(stage, DESStage::FinalPermutation);
    vec![
        ln("    ┌──────────────────────────┐", start),
        ln("    │       Input Block        │", start),
        ln("    └─────────────┬────────────┘", start),
        ln("                  │", false),
        ln("    ┌─────────────┴────────────┐", ip),
        ln("    │             IP           │", ip),
        ln("    └─────────────┬────────────┘", ip),
        ln("                  │", false),
        ln("              L ──┼── R", false),
        ln("                  │", false),
        ln("         (16 Feistel rounds)", false),
        ln("                  │", false),
        ln("             R' ──┼── L'", false),
        ln("                  │", false),
        ln("    ┌─────────────┴────────────┐", fp),
        ln("    │            IP⁻¹          │", fp),
        ln("    └─────────────┬────────────┘", fp),
        ln("                  │", false),
        ln("    ┌──────────────────────────┐", fp),
        ln("    │        Ciphertext        │", fp),
        ln("    └──────────────────────────┘", fp),
    ]
}

fn feistel_sketch(stage: &FStage) -> Vec<Line<'static>> {
    let init = matches!(stage, FStage::Init);
    let ks = matches!(stage, FStage::KeySchedule);
    let exp = matches!(stage, FStage::Expansion);
    let kw = matches!(stage, FStage::KeyWhitening);
    let sb = matches!(stage, FStage::SBox);
    let pm = matches!(stage, FStage::Permutation);
    let sx = matches!(stage, FStage::StateXor);
    let dn = matches!(stage, FStage::Done);
    vec![
        ln("    L (32-bit)                        R (32-bit)", init),
        ln("         |               |               |", init),
        ln("         |               K ──────────────┤", ks),
        ln("         |               |       ┌────────────────┐", exp),
        ln("         |               |       │   E expand     │", exp),
        ln("         |               |       └───────┬────────┘", exp),
        ln("         |               |───────────────│", kw),
        ln("         |                       ┌───────┴────────┐", kw),
        ln("         |                       │   XOR (+ K)    │", kw),
        ln("         |                       └───────┬────────┘", kw),
        ln("         |                       ┌───────┴────────┐", sb),
        ln("         |                       │   S-boxes      │", sb),
        ln("         |                       └───────┬────────┘", sb),
        ln("         |                       ┌───────┴────────┐", pm),
        ln("         |                       │   P permute    │", pm),
        ln("         |                       └───────┬────────┘", pm),
        ln("         |                               |", pm),
        ln("         |                               |", pm),
        ln("         ─────────────────────────────────", pm),
        ln("                    ┌─────┴─────┐         ", sx),
        ln("                    │    XOR    │         ", sx),
        ln("                    └─────┬─────┘", sx),
        ln("                          │", dn),
        ln("                  new R   │   new L  (swap)", dn),
    ]
}

fn sketch(step: &DESState) -> Vec<Line<'static>> {
    match &step.des_stage {
        DESStage::Round => feistel_sketch(&step.feistel_stage),
        stage => ip_sketch(stage),
    }
}

fn ui(f: &mut Frame, app: &App) {
    let step = &app.trace[app.cursor];
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(4),
        Constraint::Length(3),
    ])
    .split(f.area());

    f.render_widget(
        Paragraph::new(format!(
            " GRIFFON  DES Trace  [{}/{}]  {}",
            app.cursor + 1,
            app.trace.len(),
            app.stage_label()
        ))
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::Cyan)),
        chunks[0],
    );

    f.render_widget(
        Paragraph::new(sketch(step))
            .block(Block::default().borders(Borders::ALL).title(" Sketch ")),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(vec![
            Line::from(format!(
                "  L: 0x{:08x}    R: 0x{:016x}",
                step.state.left, step.f_state
            )),
            Line::from(format!(
                "  KL: 0x{:07x}   KR: 0x{:07x}   Sub-step: {:?}",
                step.current_key.left, step.current_key.right, step.feistel_stage
            )),
        ])
        .block(Block::default().borders(Borders::ALL).title(" State ")),
        chunks[2],
    );

    f.render_widget(
        Paragraph::new("  [←/h] prev   [→/l] next   [q] quit")
            .block(Block::default().borders(Borders::ALL)),
        chunks[3],
    );
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: griffon-cli <hex-plaintext> <hex-key>");
        std::process::exit(1);
    }
    let plaintext = parse_hex(&args[1]);
    let key = parse_hex(&args[2]);

    let mut des = canonical_builder().build(key);
    des.start(plaintext);
    for _ in 0..16 {
        des.next_round();
    }
    des.finalize();
    let trace = des.get_history().to_vec();

    println!("{:?}", trace);
    let mut app = App::new(trace);

    enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();
    let _guard = TerminalGuard;

    loop {
        terminal.draw(|f| ui(f, &app)).unwrap();
        if let Ok(Event::Key(KeyEvent {
            code,
            kind: KeyEventKind::Press,
            ..
        })) = event::read()
        {
            match code {
                KeyCode::Right | KeyCode::Char('l') => app.next(),
                KeyCode::Left | KeyCode::Char('h') => app.prev(),
                KeyCode::Char('b') => app.prev(),
                KeyCode::Char('q') | KeyCode::Esc => break,
                _ => {}
            }
        }
    }
}
