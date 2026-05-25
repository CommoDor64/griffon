use griffon::{canonical_builder, DESTraceEntry, FeistelRoundState};
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
    trace:  Vec<DESTraceEntry>,
    cursor: usize,
}

impl App {
    fn new(trace: Vec<DESTraceEntry>) -> Self {
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
        match &self.trace[self.cursor] {
            DESTraceEntry::IP { .. }    => "Initial Permutation".to_string(),
            DESTraceEntry::Round(r)     => format!("Round {}", r.round + 1),
            DESTraceEntry::FP { .. }    => "Final Permutation".to_string(),
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

fn hl(text: &'static str, active: bool) -> Line<'static> {
    if active {
        Line::from(Span::styled(
            text,
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(text)
    }
}

fn ip_sketch(is_ip: bool, is_fp: bool) -> Vec<Line<'static>> {
    vec![
        hl("    ┌──────────────────────────┐", !is_ip && !is_fp),
        hl("    │       Input Block        │", !is_ip && !is_fp),
        hl("    └─────────────┬────────────┘", !is_ip && !is_fp),
        Line::from("                  │"),
        hl("    ┌─────────────┴────────────┐", is_ip),
        hl("    │             IP           │", is_ip),
        hl("    └─────────────┬────────────┘", is_ip),
        Line::from("                  │"),
        Line::from("              L ──┼── R"),
        Line::from("                  │"),
        Line::from("         (16 Feistel rounds)"),
        Line::from("                  │"),
        Line::from("             R' ──┼── L'"),
        Line::from("                  │"),
        hl("    ┌─────────────┴────────────┐", is_fp),
        hl("    │            IP⁻¹          │", is_fp),
        hl("    └─────────────┬────────────┘", is_fp),
        Line::from("                  │"),
        hl("    ┌──────────────────────────┐", is_fp),
        hl("    │        Ciphertext        │", is_fp),
        hl("    └──────────────────────────┘", is_fp),
    ]
}

fn feistel_sketch(r: &FeistelRoundState<u32, u64>) -> Vec<Line<'static>> {
    // Show the F pipeline; all steps are always visible, none highlighted
    // (the state panel already shows the values at each sub-step).
    vec![
        Line::from(format!("  Round {}   L=0x{:08x}   R=0x{:08x}", r.round + 1, r.left, r.right)),
        Line::from(""),
        Line::from("    R (32-bit)"),
        Line::from("         │"),
        Line::from("    ┌────┴────────────┐"),
        Line::from("    │   E  expand     │"),
        Line::from("    └────┬────────────┘"),
        Line::from("         │──── XOR ────── K (round key)"),
        Line::from("    ┌────┴────────────┐"),
        Line::from("    │   S-boxes       │"),
        Line::from("    └────┬────────────┘"),
        Line::from("    ┌────┴────────────┐"),
        Line::from("    │   P  permute    │"),
        Line::from("    └────┬────────────┘"),
        Line::from("         │"),
        Line::from("    L ───┴─── XOR ──► new R   (L → new L)"),
    ]
}

fn sketch(entry: &DESTraceEntry) -> Vec<Line<'static>> {
    match entry {
        DESTraceEntry::IP { .. }    => ip_sketch(true, false),
        DESTraceEntry::FP { .. }    => ip_sketch(false, true),
        DESTraceEntry::Round(r)     => feistel_sketch(r),
    }
}

fn state_lines(entry: &DESTraceEntry) -> Vec<Line<'static>> {
    match entry {
        DESTraceEntry::IP { input, output } => vec![
            Line::from(format!("  Input:  0x{input:016x}")),
            Line::from(format!("  Output: 0x{output:016x}  (after IP)")),
        ],
        DESTraceEntry::FP { input, output } => vec![
            Line::from(format!("  Input:  0x{input:016x}  (pre-IP⁻¹)")),
            Line::from(format!("  Output: 0x{output:016x}  (ciphertext)")),
        ],
        DESTraceEntry::Round(r) => vec![
            Line::from(format!(
                "  L: 0x{:08x}   R: 0x{:08x}   K: 0x{:012x}",
                r.left, r.right, r.round_key
            )),
            Line::from(format!(
                "  expand→0x{:012x}  xor→0x{:012x}  sbox→0x{:08x}  p→0x{:08x}",
                r.f_trace.after_expand,
                r.f_trace.after_key_mix,
                r.f_trace.after_substitute,
                r.f_trace.after_permute,
            )),
        ],
    }
}

fn ui(f: &mut Frame, app: &App) {
    let entry = &app.trace[app.cursor];
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
        Paragraph::new(sketch(entry))
            .block(Block::default().borders(Borders::ALL).title(" Sketch ")),
        chunks[1],
    );

    f.render_widget(
        Paragraph::new(state_lines(entry))
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
    let key       = parse_hex(&args[2]);

    let mut des = canonical_builder().build(key);
    let (_, trace) = des.encrypt(plaintext);
    let app = App::new(trace);

    enable_raw_mode().unwrap();
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen).unwrap();
    let backend  = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).unwrap();
    let _guard = TerminalGuard;

    let mut app = app;
    loop {
        terminal.draw(|f| ui(f, &app)).unwrap();
        if let Ok(Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. })) = event::read() {
            match code {
                KeyCode::Right | KeyCode::Char('l') => app.next(),
                KeyCode::Left  | KeyCode::Char('h') => app.prev(),
                KeyCode::Char('q') | KeyCode::Esc   => break,
                _ => {}
            }
        }
    }
}
