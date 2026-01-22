# iptr-edge-analyzer

`iptr-edge-analyzer` is a core crate of [`iptr`](https://github.com/Evian-Zhang/iptr) project, providing capabilities of extracting edges and branches in Intel PT traces, and constructing AFL++-compatible fuzzing bitmaps. This crate is designed to be used with [`iptr-decoder`](https://crates.io/crates/iptr-decoder) together.

To use this crate, add this crate to your `Cargo.toml`:

```toml
[dependencies]
iptr-edge-analyzer = "0.1"
```

## Background Knowledge

The ultimate goal for this crate is to re-construct the branch transition sequence from the Intel PT trace. In the Intel PT format, TNT and TIP packets are two most common packets to record such information. For the performance consideration, the Intel PT format needs to ensure that we should be able to use the trace to reconstruct the program's whole execution in instruction level without information lost, and sill be small enough in size (otherwise the IO would be very large). In light of this consideration, Intel PT format takes the following decisions:

1. The determined branch transitions can be omitted.

   Unconditional direct jumps and direct calls are determined branch transitions, meaning that if a basic block ends with an unconditional direct call, then when we reach that block, we can make sure that the next block will always be the target of the direct call (if we don't consider the interruptions). As a result, we can record the first basic block only, omitting the next determined block address.
2. The statically-known branch transitions can be "compressed".

   The targets of conditional direct jumps can be known without runtime execution. As a result, we don't need to record the full address of a jump target. Instead, we can only record the taken/not-taken result of that branch. This is what TNT packets are for: one short TNT packets will record the results of at most six consecutive conditional direct jumps.

Based on the two decisions described above, the Intel PT format will only record the whole target address in a TIP packet for an indirect jump or indirect call (`jmp *%rax`), and omit the unconditional jumps/calls and compress conditional jumps in TNT packets. For interruptions, FUP packets will be emitted to record the target of interruption handler.

As the goal of this crate is to re-construct the branch transition sequence, the design of Intel PT format forces us to also **require content of the whole executable memory areas**. Since TNT packets only records the taken/not taken result of a conditional jump, we need to decode every instruction since a TIP packet to get the target address of every conditional jump, and also re-construct the omitted unconditional jumps/calls.

## Basic Usage (non-cache)

The whole crate is centered around one struct [`EdgeAnalyzer`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/struct.EdgeAnalyzer.html) and two traits [`ControlFlowHandler`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/control_flow_handler/trait.HandleControlFlow.html) and [`MemoryReader`](https://docs.rs/iptr-edge-analyzer/latest/iptr_edge_analyzer/memory_reader/trait.ReadMemory.html).
