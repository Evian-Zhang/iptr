# iptr-perf-pt-extractor

`iptr-perf-pt-extractor` will extract raw Intel PT trace from `perf.data` file.

For now, this tool will not examine whether the `perf.data` is recorded with Intel PT or not.

## Build and install

You should install the lastest rust compiler toolset, and follow the following instructions:

```shell
git clone --depth 1 https://github.com/Evian-Zhang/iptr
cd iptr/tools/iptr-perf-pt-extractor
RUSTFLAGS="-C target-cpu=native" cargo build --release
```

Then the executable will be generated at `iptr/target/release/iptr-perf-pt-extractor`.

## Usage

```plaintext
./iptr-perf-pt-extractor --help
Extract Intel PT aux data from perf.data

Set the environment variable `RUST_LOG=trace` for logging.

Usage: iptr-perf-pt-extractor [OPTIONS] --input <INPUT> --output <OUTPUT>

Options:
  -i, --input <INPUT>
          Path of perf.data

  -o, --output <OUTPUT>
          Path for output.
          
          If no `--first-only` is specified, this path should refer to a directory, all PT traces inside the perf.data will be extracted into that directory; if `--first-only` is specified, this option is used for the file path for extracted PT trace.

      --first-only
          Only extract the first PT trace, ignoring all others

  -h, --help
          Print help (see a summary with '-h')
```
