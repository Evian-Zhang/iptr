# iptr-edge-analyzer

`iptr-edge-analyzer` is a core crate of [`iptr`](https://github.com/Evian-Zhang/iptr) project, providing capabilities of extracting edges and branches in Intel PT traces, and constructing AFL++-compatible fuzzing bitmaps. This crate is designed to be used with [`iptr-decoder`](https://crates.io/crates/iptr-decoder) together.

To use this crate, add this crate to your `Cargo.toml`:

```toml
[dependencies]
iptr-edge-analyzer = "0.1"
```

## Background Knowledge

## Basic Usage (non-cache)

The whole crate is centered around one struct [`EdgeAnalyzer`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/struct.EdgeAnalyzer.html) and two traits [`ControlFlowHandler`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/control_flow_handler/trait.HandleControlFlow.html) and [`MemoryReader`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/memory_reader/trait.ReadMemory.html).
