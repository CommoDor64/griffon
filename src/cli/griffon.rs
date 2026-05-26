use clap::{Parser, ValueEnum};
use griffon::{canonical_builder, DESTraceEntry};
use std::{fs, path::PathBuf};

#[derive(Clone, PartialEq, ValueEnum)]
enum Step {
    Expand,
    KeyMix,
    Substitute,
    Permute,
}

#[derive(Clone, Default, ValueEnum)]
enum Format {
    #[default]
    Hex,
    Bin,
}

fn fmt64(v: u64, f: &Format) -> String {
    match f {
        Format::Hex => format!("0x{v:016x}"),
        Format::Bin => format!("0b{v:064b}"),
    }
}

fn fmt32(v: u32, f: &Format) -> String {
    match f {
        Format::Hex => format!("0x{v:08x}"),
        Format::Bin => format!("0b{v:032b}"),
    }
}

fn fmt48(v: u64, f: &Format) -> String {
    match f {
        Format::Hex => format!("0x{v:012x}"),
        Format::Bin => format!("0b{v:048b}"),
    }
}

#[derive(Parser)]
#[command(name = "griffon-cli", about = "DES trace viewer")]
struct Cli {
    plaintext: String,
    key: String,
    #[arg(long, value_enum, default_value_t = Format::Hex)]
    format: Format,
    #[arg(long, default_value_t = 16)]
    rounds: usize,
    #[arg(long, value_enum, value_delimiter = ',', num_args = 0..)]
    skip: Vec<Step>,
    #[arg(long, value_name = "FILE")]
    export: Option<PathBuf>,
}

fn parse_hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x").trim_start_matches("0X"), 16)
        .unwrap_or_else(|e| {
            eprintln!("invalid hex '{s}': {e}");
            std::process::exit(1);
        })
}

fn stage_label(entry: &DESTraceEntry) -> String {
    match entry {
        DESTraceEntry::IP { .. }    => "Initial Permutation".to_string(),
        DESTraceEntry::Round(r)     => format!("Round {:2}", r.round + 1),
        DESTraceEntry::FP { .. }    => "Final Permutation".to_string(),
    }
}

fn print_trace(plaintext: u64, key: u64, ciphertext: u64, trace: &[DESTraceEntry], fmt: &Format, skip: &[Step]) {
    let total = trace.len();
    println!("=== DES Trace ===");
    println!("Plaintext:  {}", fmt64(plaintext, fmt));
    println!("Key:        {}", fmt64(key, fmt));
    println!("Ciphertext: {}", fmt64(ciphertext, fmt));

    for (i, entry) in trace.iter().enumerate() {
        println!();
        println!("[{:2} / {:2}]  {}", i + 1, total, stage_label(entry));
        match entry {
            DESTraceEntry::IP { input, output } => {
                println!("  input:   {}", fmt64(*input, fmt));
                println!("  output:  {}", fmt64(*output, fmt));
            }
            DESTraceEntry::FP { input, output } => {
                println!("  input:   {}", fmt64(*input, fmt));
                println!("  output:  {}", fmt64(*output, fmt));
            }
            DESTraceEntry::Round(r) => {
                println!("  left:      {}", fmt32(r.left, fmt));
                println!("  right:     {}", fmt32(r.right, fmt));
                println!("  round_key: {}", fmt48(r.round_key, fmt));
                let shown: Vec<_> = [
                    (!skip.contains(&Step::Expand),     "expand",     fmt48(r.f_trace.after_expand, fmt)),
                    (!skip.contains(&Step::KeyMix),     "key_mix",    fmt48(r.f_trace.after_key_mix, fmt)),
                    (!skip.contains(&Step::Substitute), "substitute", fmt32(r.f_trace.after_substitute, fmt)),
                    (!skip.contains(&Step::Permute),    "permute",    fmt32(r.f_trace.after_permute, fmt)),
                ].into_iter().filter(|(show, _, _)| *show).collect();
                if !shown.is_empty() {
                    println!("  f-steps:");
                    for (_, label, val) in shown {
                        println!("    {label:<12}{val}");
                    }
                }
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let plaintext = parse_hex(&cli.plaintext);
    let key       = parse_hex(&cli.key);

    let mut des = canonical_builder().rounds(cli.rounds).build(key);
    let (ciphertext, trace) = des.encrypt(plaintext);

    match cli.export {
        Some(path) => {
            let json = serde_json::to_string_pretty(&trace).unwrap();
            if path.to_str() == Some("-") {
                println!("{json}");
            } else {
                fs::write(&path, &json).unwrap_or_else(|e| {
                    eprintln!("error writing {}: {e}", path.display());
                    std::process::exit(1);
                });
                eprintln!("trace written to {}", path.display());
            }
        }
        None => print_trace(plaintext, key, ciphertext, &trace, &cli.format, &cli.skip),
    }
}
