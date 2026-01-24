# iptr

`iptr` is a Rust project to interact with Intel PT traces, providing both low-level PT packet handling and high-level AFL++-compatible fuzzing bitmap construction.

This repository is organized in the following structure, please refer to individual documentations for more details.

* [`iptr-decoder`](./iptr-decoder/README.md)

   Low-level Intel PT trace handling APIs.
* [`iptr-edge-analyzer`](./iptr-edge-analyzer/README.md)

   Branch and basic block information in Intel PT trace. Also provides a powerful efficient AFL++-compatible fuzzing bitmap construction approach.
* [`iptr-perf-pt-reader`](./iptr-perf-pt-reader/README.md)

   Extract necessary information from `perf.data`.
* tools

   Example tools of using this project. Useful tools including:
   * [`iptr-raw-logger`](./tools/iptr-raw-logger/README.md)

      Decode and log details for Intel PT packets
   * [`iptr-perf-pt-extractor`](./tools/iptr-perf-pt-extractor/README.md)

      Extract raw Intel PT trace from `perf.data` file.
   * [`iptr-perf-pt-analyzer`](./tools/iptr-perf-pt-analyzer/README.md)

      Decode the Intel PT trace in perf.data file with semantic validation.
   * [`iptr-perf-memory-extractor`](./tools/iptr-perf-memory-extractor/README.md)

      Extract memory content in `perf.data` file into libxdc experiments format.