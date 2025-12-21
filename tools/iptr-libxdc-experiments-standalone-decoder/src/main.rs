mod control_flow_handler;
mod memory_reader;

use std::{fs::File, path::PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use iptr_decoder::DecodeOptions;
use iptr_edge_analyzer::{EdgeAnalyzer, diagnose::DiagnosticInformation};

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
    env_logger::init();

    let Cmdline {
        input,
        page_dump,
        page_addr,
    } = Cmdline::parse();

    let mut memory_reader =
        MemoryReader::new(&page_dump, &page_addr).context("Failed to create memory reader")?;
    let mut control_flow_handler = FuzzBitmapControlFlowHandler::default();
    let edge_analyzer = EdgeAnalyzer::new(&mut control_flow_handler, &mut memory_reader);
    #[cfg(feature = "debug")]
    let mut packet_handler = iptr_decoder::packet_handler::combined::CombinedPacketHandler::new(
        iptr_decoder::packet_handler::log::PacketHandlerRawLogger::default(),
        edge_analyzer,
    );
    #[cfg(not(feature = "debug"))]
    let mut packet_handler = edge_analyzer;

    let file = File::open(input).context("Failed to open input file")?;
    // SAFETY: check the safety requirements of memmap2 documentation
    let buf = unsafe { memmap2::Mmap::map(&file).context("Failed to mmap input file")? };

    iptr_decoder::decode(&buf, DecodeOptions::default(), &mut packet_handler).unwrap();

    #[cfg(feature = "debug")]
    let (_, edge_analyzer) = packet_handler.into_inner();
    #[cfg(not(feature = "debug"))]
    let edge_analyzer = packet_handler;

    let DiagnosticInformation {
        cfg_size,
        cache8_size,
        cache32_size,
    } = edge_analyzer.diagnose();
    log::info!(
        "After analyzer, CFG size {cfg_size}, 8bit cache size {cache8_size}, 32bit cache size {cache32_size}"
    );

    Ok(())
}
