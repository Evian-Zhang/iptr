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

Another worth-noting thing is that, Intel PT uses "Indirect Transfer Compression for Returns" to further compress the total size of Intel PT traces. This requires the decoder to maintain a call stack, which will incur a lot of memory pressure and performance overhead when performing some sort of caching. As a result, we do not support Intel PT traces recorded with return compression on.

## Non-cache Mode Usage

The whole crate is centered around one struct [`EdgeAnalyzer`][EdgeAnalyzer] and two traits [`HandleControlFlow`][HandleControlFlow] and [`ReadMemory`][ReadMemory]. [`EdgeAnalyzer`][EdgeAnalyzer] implements [`HandlePacket`](https://docs.rs/iptr-decoder/latest/iptr_decoder/trait.HandlePacket.html), and thus can be used with [`iptr-decoder`](https://crates.io/crates/iptr-decoder)'s [`decode`](https://docs.rs/iptr-decoder/latest/iptr_decoder/fn.decode.html) function to perform decoding on Intel PT traces.

An [`EdgeAnalyzer`][EdgeAnalyzer] should be created with a struct implementing [`HandleControlFlow`][HandleControlFlow] and a struct implementing [`ReadMemory`][ReadMemory]. For [`HandleControlFlow`][HandleControlFlow], such a struct provides callbacks when a new basic block is encountered. The struct that implementing [`ReadMemory`][ReadMemory] is more important. As mentioned in the preliminary knowledge, this crate needs the content of whole executable memory areas, and that is what [`ReadMemory`][ReadMemory] is for. For simple usage, where the Intel PT trace is recorded by `perf` tool, this crate provides [`PerfMmapBasedMemoryReader`][PerfMmapBasedMemoryReader] which implements [`ReadMemory`][ReadMemory]. It should be noted that the `perf` tool does not necessarily dump the whole memory content into the `perf.data` file. Instead, the `perf.data` file only records the `mmap` operation. As a result, we need to make sure that all binaries involved should remain unmodified at their original paths, and the [`PerfMmapBasedMemoryReader`][PerfMmapBasedMemoryReader] will reconstruct the memory content according to the paths of `mmap` operations recorded in the `perf.data` file.

As a result, a typical usage of [`EdgeAnalyzer`][EdgeAnalyzer] to decode Intel-PT traces stored in a `perf.data` file can be minimized into the following code snippet, which utilized [`iptr-perf-pt-reader`](https://crates.io/crates/iptr-perf-pt-reader) to parse `perf.data` file, and [`iptr-decoder`](https://crates.io/crates/iptr-decoder) to drive the [`EdgeAnalyzer`][EdgeAnalyzer] for decoding Intel PT traces.

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
    let (pt_traces, mmapped_headers) =
        iptr_perf_pt_reader::extract_pt_auxtraces_and_mmap_data(perf_data_content).unwrap();
    let memory_reader = PerfMmapBasedMemoryReader::new(&mmapped_headers).unwrap();
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

This crate provides a `LogControlFlowHandler`, which has the similar functionalities as the `MyControlFlowHandler` shown above.

`LogControlFlowHandler` can be perfectly integrated into your own workflow with the [`CombinedControlFlowHandler`][CombinedControlFlowHandler]. This struct also implements [`HandleControlFlow`][HandleControlFlow], and takes two arbitrary structs that implement [`HandleControlFlow`][HandleControlFlow] and combine their functionalities. A typical working example is like below:

```rust,ignore
use iptr_edge_analyzer::control_flow_handler::{
    combined::CombinedControlFlowHandler,
    log::LogControlFlowHandler,
};

let log_control_flow_handler = LogControlFlowHandler::default();
let my_control_flow_handler = MyControlFlowHandler;
let control_flow_handler = CombinedControlFlowHandler::new(
    log_control_flow_handler,
    my_control_flow_handler,
);
// Use `control_flow_handler` ...
```

With the pattern shown above, we can easily debug `MyControlFlowHandler` at prototype stage, since the `log_control_flow_handler` can log every block information.

## Cache Mode Usage

This crate has a feature `cache`. When enable this feature, you can enjoy ultra fast Intel PT decoding. The overall design is inspired by [`libxdc`](https://github.com/nyx-fuzz/libxdc). The design is based on the insight that during the execution of a process, there are always a large number of loops, and several functions are invoked multiple times. As a result, some fixed patterns of TIP-TNT packets can be occurred very common. Moreover, in the fuzzing process, the executions between each rounds are also very common. As a result, we can cache the decoding results, and thus boost the performance.

When enabling `cache` feature, you can observe that the definition of [`HandleControlFlow`][HandleControlFlow] has changed, there are new associated types and new methods for users to implement. Although we have modelled the cache-mode control flow handler in a correct and user-friendly manner, it's still challenging to write a correct implementor for cache-mode [`HandleControlFlow`][HandleControlFlow]. So before you want to manually implement [`HandleControlFlow`][HandleControlFlow], you should refer to its documentation and make sure you understand every details. Note that `LogControlFlowHandler` is not available in cache-mode since enabling logging in cache mode will make it slow down dramatically due to the additional storage required to cache, making it meaningless to use cache mode.

We provide a [`FuzzBitmapControlFlowHandler`][FuzzBitmapControlFlowHandler] that implements the cache-mode [`HandleControlFlow`][HandleControlFlow]. This struct takes a bitmap as input, and updates the bitmap at each basic block callback in an AFL++-compatible manner. The usage of this struct is straightforward.

```rust
use iptr_decoder::DecodeOptions;
use iptr_edge_analyzer::{
    EdgeAnalyzer,
    control_flow_handler::fuzz_bitmap::FuzzBitmapControlFlowHandler,
    memory_reader::perf_mmap::PerfMmapBasedMemoryReader,
};

fn process_intel_pt(intel_pt: &[u8], fuzzing_bitmap: &mut [u8], memory_reader: PerfMmapBasedMemoryReader) {
    let control_flow_handler = FuzzBitmapControlFlowHandler::new(fuzzing_bitmap, None);
    let mut edge_analyzer = EdgeAnalyzer::new(control_flow_handler, memory_reader);
    iptr_decoder::decode(intel_pt, DecodeOptions::default(), &mut edge_analyzer).unwrap();
    // At this moment, `fuzzing_bitmap` is updated in an AFL++-compatible manner
}
```

It should be noted that, [`CombinedControlFlowHandler`][CombinedControlFlowHandler] also supports cache mode, and [`FuzzBitmapControlFlowHandler`][FuzzBitmapControlFlowHandler] also supports non-cache mode (although this usage should be discouraged, since it would be very slow).

## Features

This crate has the following features:

* `cache`

   Enable the cache mode.

   This feature is not enabled by default.
* `more_diagnose`

   Add more diagnostic information in the [`DiagnosticInformation`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/struct.DiagnosticInformation.html) structure. These information would impose a little performance overhead, but is very useful for debugging.

   This feature is not enabled by default.
* `fuzz_bitmap`

   Enable [`FuzzBitmapControlFlowHandler`][FuzzBitmapControlFlowHandler]. This struct implements [`HandleControlFlow`][HandleControlFlow] and will construct an AFL++-compatible fuzzing bitmap.

   This feature is not enabled by default.
* `perf_memory_reader`

   Enable [`PerfMmapBasedMemoryReader`][PerfMmapBasedMemoryReader]. This struct implements [`ReadMemory`][ReadMemory] and will re-construct the memory layout according to the mmap operations recorded in the `perf.data` files.

   This feature is not enabled by default.
* `libxdc_memory_reader`

   Enable [`LibxdcMemoryReader`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/memory_reader/libxdc/struct.LibxdcMemoryReader.html). This struct implements [`ReadMemory`][ReadMemory] and will re-construct the memory layout from the address and dump file format used in libxdc experiments.

   This feature is not enabled by default.
* `log_control_flow_handler`

   Enable `LogControlFlowHandler`. This struct implements [`HandleControlFlow`][HandleControlFlow] and will log basic block information at each callback. Note that the struct is only enabled if `cache` feature is not enabled.

   This feature is not enabled by default.

[EdgeAnalyzer]: https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/struct.EdgeAnalyzer.html
[HandleControlFlow]: https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/control_flow_handler/trait.HandleControlFlow.html
[ReadMemory]: https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/memory_reader/trait.ReadMemory.html
[CombinedControlFlowHandler]: https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/control_flow_handler/combined/struct.CombinedControlFlowHandler.html
[FuzzBitmapControlFlowHandler]: https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/control_flow_handler/fuzz_bitmap/FuzzBitmapControlFlowHandler
[PerfMmapBasedMemoryReader]: https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/memory_reader/perf_mmap/struct.PerfMmapBasedMemoryReader.html
