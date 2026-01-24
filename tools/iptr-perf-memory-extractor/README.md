# iptr-perf-memory-extractor

`iptr-perf-memory-extractor` will extract memory content in `perf.data` file into libxdc experiments format.

## Build and install

You should install the lastest rust compiler toolset, and follow the following instructions:

```shell
git clone --depth 1 https://github.com/Evian-Zhang/iptr
cd iptr/tools/iptr-perf-memory-extractor
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Then the executable will be generated at `iptr/target/release/iptr-perf-memory-extractor`.

## Usage

```plaintext
./iptr-perf-memory-extractor --help
Create libxdc-experiments-compatible memory dump.

Set the environment variable `RUST_LOG=trace` for logging.

Usage: iptr-perf-memory-extractor --input <INPUT> --page-dump <PAGE_DUMP> --page-addr <PAGE_ADDR>

Options:
  -i, --input <INPUT>
          Path of intel PT trace in perf.data format

      --page-dump <PAGE_DUMP>
          Path for generated page dump

      --page-addr <PAGE_ADDR>
          Path for generated page address

  -h, --help
          Print help (see a summary with '-h')
```
