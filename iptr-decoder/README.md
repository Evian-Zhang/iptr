# iptr-decoder

`iptr-decoder` is a crate of [`iptr`](https://github.com/Evian-Zhang/iptr) project, providing idiomatic Rust-style low-level Intel PT trace handling APIs.

To use this crate, add this crate to your `Cargo.toml`:

```toml
iptr-decoder = "0.1"
```

## Basic usage

The core functionalities are designed with the trait `HandlePacket`. 
