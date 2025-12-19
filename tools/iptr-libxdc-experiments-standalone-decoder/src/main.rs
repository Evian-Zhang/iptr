mod control_flow_handler;
mod memory_reader;

use std::{fs::File, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use iptr_decoder::DecodeOptions;
use iptr_edge_analyzer::EdgeAnalyzer;

use crate::{control_flow_handler::FuzzBitmapControlFlowHandler, memory_reader::MemoryReader};

#[derive(Parser)]
struct Cmdline {
    #[arg(short, long)]
    input: PathBuf,
    #[arg(long)]
    page_dump: PathBuf,
    #[arg(long)]
    page_addr: PathBuf,
}

fn main() -> Result<()> {
    let Cmdline {
        input,
        page_dump,
        page_addr,
    } = Cmdline::parse();

    let mut memory_reader =
        MemoryReader::new(&page_dump, &page_addr).context("Failed to create memory reader")?;
    let mut control_flow_handler = FuzzBitmapControlFlowHandler::default();
    let mut edge_analyzer = EdgeAnalyzer::new(&mut control_flow_handler, &mut memory_reader);

    let file = File::open(input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };

    iptr_decoder::decode(&buf, DecodeOptions::default(), &mut edge_analyzer).unwrap();

    Ok(())
}
