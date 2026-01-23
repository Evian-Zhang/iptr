# iptr-edge-analyzer

`iptr-edge-analyzer` is a core crate of [`iptr`](https://github.com/Evian-Zhang/iptr) project, providing capabilities of extracting edges and branches in Intel PT traces, and constructing AFL++-compatible fuzzing bitmaps. This crate is designed to be used with [`iptr-decoder`](https://crates.io/crates/iptr-decoder) together.

To use this crate, add this crate to your `Cargo.toml`:

```toml
[dependencies]
iptr-edge-analyzer = "0.1"
```

## Preliminary Knowledge

The ultimate goal for this crate is to re-construct the branch transition sequence from the Intel PT trace. In the Intel PT format, TNT and TIP packets are two most common packets to record such information. For the performance consideration, the Intel PT format needs to ensure that we should be able to use the trace to reconstruct the program's whole execution in instruction level without information lost, and sill be small enough in size (otherwise the IO would be very large). In light of this consideration, Intel PT format takes the following decisions:

1. The determined branch transitions can be omitted.

   Unconditional direct jumps and direct calls are determined branch transitions, meaning that if a basic block ends with an unconditional direct call, then when we reach that block, we can make sure that the next block will always be the target of the direct call (if we don't consider the interruptions). As a result, we can record the first basic block only, omitting the next determined block address.
2. The statically-known branch transitions can be "compressed".

   The targets of conditional direct jumps can be known without runtime execution. As a result, we don't need to record the full address of a jump target. Instead, we can only record the taken/not-taken result of that branch. This is what TNT packets are for: one short TNT packets will record the results of at most six consecutive conditional direct jumps.

Based on the two decisions described above, the Intel PT format will only record the whole target address in a TIP packet for an indirect jump or indirect call (`jmp *%rax`), and omit the unconditional jumps/calls and compress conditional jumps in TNT packets. For interruptions, FUP packets will be emitted to record the target of interruption handler.

As the goal of this crate is to re-construct the branch transition sequence, the design of Intel PT format forces us to also **require content of the whole executable memory areas**. Since TNT packets only records the taken/not-taken result of a conditional jump, we need to decode every instruction since a TIP packet to get the target address of every conditional jump, and also re-construct the omitted unconditional jumps/calls.

## Non-cache Usage

The whole crate is centered around one struct [`EdgeAnalyzer`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/struct.EdgeAnalyzer.html) and two traits [`HandleControlFlow`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/control_flow_handler/trait.HandleControlFlow.html) and [`ReadMemory`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/memory_reader/trait.ReadMemory.html). `EdgeAnalyzer` implements [`HandlePacket`](https://docs.rs/iptr-decoder/latest/iptr_decoder/trait.HandlePacket.html), and thus can be used with `iptr-decoder`'s [`decode`](https://docs.rs/iptr-decoder/latest/iptr_decoder/fn.decode.html) function to perform decoding on Intel PT traces.

An `EdgeAnalyzer` should be created with a struct implementing `HandleControlFlow` and a struct implementing `ReadMemory`. For `HandleControlFlow`, such a struct provides callbacks when a new basic block is encountered. The struct that implementing `ReadMemory` is more important. As mentioned in the preliminary knowledge, this crate needs the content of whole executable memory areas, and that is what `ReadMemory` is for. For simple usage, where the Intel PT trace is recorded by `perf` tool, this crate provides [`PerfMmapBasedMemoryReader`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/memory_reader/perf_mmap/struct.PerfMmapBasedMemoryReader.html) which implements `ReadMemory`. It should be noted that the `perf` tool does not necessarily dump the whole memory content into the `perf.data` file. Instead, the `perf.data` file only records the `mmap` operation. As a result, we need to make sure that all binaries involved should remain unmodified at their original paths, and the `PerfMmapBasedMemoryReader` will reconstruct the memory content according to the paths of `mmap` operations recorded in the `perf.data` file.

As a result, a typical usage of `EdgeAnalyzer` to decode Intel-PT traces stored in a `perf.data` file can be minimized into the following code snippet, which utilized [`iptr-perf-pt-reader`](https://crates.io/crates/iptr-perf-pt-reader) to parse `perf.data` file, and [`iptr-decoder`](https://crates.io/crates/iptr-decoder) to drive the `EdegeAnalyzer` for decoding Intel PT traces.

```rust,ignore
use iptr_decoder::DecodeOptions;
use iptr_edge_analyzer::{
    EdgeAnalyzer,
    control_flow_handler::{ControlFlowTransitionKind, HandleControlFlow},
    memory_reader::perf_mmap::PerfMmapBasedMemoryReader,
};

struct MyControlFlowHandler;
impl HandleControlFlow for MyControlFlowHandler {
    // We don't produce high-level errors for simplicity
    type Error = std::convert::Infallible;
    fn at_decode_begin(&mut self) -> Result<(), Self::Error> { Ok(()) }
    // Will be invoked every time a block is encountered (no matter whether it has
    // been encountered before).
    // `block_addr` is the address of basic block, `transition_kind` is how the
    // basic block is encounted, and `cache` is useless in non-cache mode.
    fn on_new_block(
        &mut self,
        block_addr: u64,
        transition_kind: ControlFlowTransitionKind,
        _cache: bool,
    ) -> Result<(), Self::Error> {
        println!("Block {block_addr:#x} encountered via {transition_kind}");
        Ok(())
    }
}

fn handle_perf_data(perf_data_content: &[u8]) {
    let (pt_traces, mmaped_headers) =
        iptr_perf_pt_reader::extract_pt_auxtraces_and_mmap_data(perf_data_content).unwrap();
    let memory_reader = PerfMmapBasedMemoryReader::new(&mmaped_headers).unwrap();
    let control_flow_handler = MyControlFlowHandler;
    let mut edge_analyzer = EdgeAnalyzer::new(control_flow_handler, memory_reader);
    for pt_trace in pt_traces {
        iptr_decoder::decode(
            pt_trace.auxtrace_data,
            DecodeOptions::default(),
            &mut edge_analyzer,
        ).unwrap();
    }
}
```
