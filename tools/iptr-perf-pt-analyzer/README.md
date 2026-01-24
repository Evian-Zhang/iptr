# iptr-perf-pt-analyzer

`iptr-perf-pt-analyzer` will decode the Intel PT trace in perf.data file with semantic validation.

This tool will do nothing if an Intel PT trace is semantically correct. However, if something is wrong, this tool will return error. Examples of semantic error is like: current basic block ends with an indirect jump, while there is no TIP packet (even deferred) available.

## Build and install

You should install the lastest rust compiler toolset, and follow the following instructions:

```shell
git clone --depth 1 https://github.com/Evian-Zhang/iptr
cd iptr/tools/iptr-perf-pt-analyzer
RUSTFLAGS="-C target-cpu=native" cargo build --profile release-with-debug
```

This tool also supports a feature flag `debug`, which will enable debug logging for each low level packets. Pass `--features debug` to the build command to enable this feature flag.

Then the executable will be generated at `iptr/target/release-with-debug/iptr-perf-pt-analyzer`.

## Usage

```plaintext
./iptr-perf-pt-analyzer --help
Decode the Intel PT trace with semantic validation.

Set the environment variable `RUST_LOG=trace` for logging.

Usage: iptr-perf-pt-analyzer --input <INPUT>

Options:
  -i, --input <INPUT>
          Path of intel PT trace in perf.data format

  -h, --help
          Print help (see a summary with '-h')
```
