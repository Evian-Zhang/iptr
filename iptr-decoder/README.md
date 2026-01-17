# iptr-decoder

`iptr-decoder` is a crate of [`iptr`](https://github.com/Evian-Zhang/iptr) project, providing idiomatic Rust-style low-level Intel PT trace handling APIs.

To use this crate, add this crate to your `Cargo.toml`:

```toml
[dependencies]
iptr-decoder = "0.1"
```

## Basic usage

The core functionalities are designed within the trait [`HandlePacket`](https://docs.rs/iptr-decoder/latest/iptr_decoder/trait.HandlePacket.html). A typical usage example is like the following code snippet.

```rust
use iptr_decoder::{DecoderContext, DecodeOptions, HandlePacket};

struct MyPtHandler;

impl HandlePacket for MyPtHandler {
    // We don't produce high-level errors for simplicity
    type Error = std::convert::Infallible;

    // Required method, will be invoked at the begining of decoding
    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    // One of the provided methods, will be invoked when a short
    // TNT packet is encountered. The actual byte is `packet_byte`, and
    // `highest_bit` refers to the index of highest bit that represents
    // a Taken/Not-Taken bit.
    fn on_short_tnt_packet(
        &mut self,
        context: &DecoderContext,
        packet_byte: std::num::NonZero<u8>,
        highest_bit: u32,
    ) -> Result<(), Self::Error> {
        println!("Short TNT packet get! Byte is {packet_byte:x}");
        Ok(())
    }
}

// Use the defined `MyPtHandler` to decode Intel PT traces
fn handle_pt_trace(pt: &[u8]) {
    let mut packet_handler = MyPtHandler;
    iptr_decoder::decode(pt, DecodeOptions::default(), &mut packet_handler).unwrap();
}
```

The `HandlePacket` trait has a lot of provided methods, each of which is corresponding to a type of PT packet. When a PT packet is decoded, the right method will be invoked with extracted values. The default implementation for each packet handlers is an NOP, and you can override each implementation like the code snippet above.

## Supported PT packet types

<details>
<summary>List of supported PT packet types</summary>

- [x] Short TNT
- [x] Long TNT
- [x] TIP
- [x] TIP.PGE
- [x] TIP.PGD
- [x] FUP
- [x] PIP
- [x] MODE
- [x] TraceStop
- [x] CBR
- [x] TSC
- [x] MTC
- [x] TMA
- [x] CYC
- [x] VMCS
- [x] OVF
- [x] PSB
- [x] PSBEND
- [x] MNT
- [x] PAD
- [x] PTW
- [x] EXSTOP
- [x] MWAIT
- [x] PWRE
- [x] RWRX
- [x] BBP
- [x] BIP
- [x] BEP
- [x] CFE
- [x] EVD
</details>

## Advanced Usage

Apart from customized `HandlePacket` implementors, this crate also provides some common packet handlers, which are organized in the [`iptr_decoder::packet_handler`](https://docs.rs/iptr-decoder/latest/iptr_decoder/packet_handler/index.html) module.

For example, the [`PacketHandlerRawLogger`](https://docs.rs/iptr-decoder/latest/iptr_decoder/packet_handler/log/struct.PacketHandlerRawLogger.html) logs all packet's information, and [`PacketCounter`](https://docs.rs/iptr-decoder/latest/iptr_decoder/packet_handler/packet_counter/struct.PacketCounter.html) can tell us how many PT packets are decoded in total.

Moreover, we provide a powerful [`CombinedPacketHandler`](https://docs.rs/iptr-decoder/latest/iptr_decoder/packet_handler/combined/struct.CombinedPacketHandler.html). With this structure, you can use the provided common packet handlers alongwith your own customized `HandlePacket` implementors:

```rust
use iptr_decoder::{
    DecodeOptions, DecoderContext, HandlePacket,
    packet_handler::{combined::CombinedPacketHandler, log::PacketHandlerRawLogger},
};

struct MyPtHandler;
impl HandlePacket for MyPtHandler {
    type Error = std::convert::Infallible;
    fn at_decode_begin(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
    // Other methods...
}

fn handle_pt_trace(pt: &[u8]) {
    let my_packet_handler = MyPtHandler;
    let log_handler = PacketHandlerRawLogger::default();
    let mut packet_handler = CombinedPacketHandler::new(log_handler, my_packet_handler);
    iptr_decoder::decode(pt, DecodeOptions::default(), &mut packet_handler).unwrap();
}
```

When running the `handle_pt_trace`, both the `log_handler` and `my_packet_handler` will be invoked, which is very useful when debugging your own packet handler.

If you want to get the branch and basic block information, you can refer to the iptr-edge-analyzer crate, which provides a more comprehensive, complex and efficient solution.

## Features

This crate has the following features:

* `log_handler`

   Enable [`iptr_decoder::packet_handler::log`](https://docs.rs/iptr-decoder/latest/iptr_decoder/packet_handler/log/index.html), which includes handler for logging low level packets.

   This feature is not enabled by default.
* `alloc`

   Enable the alloc dependency. Used only for `log_handler` feature for now.

   This feature is not enabled by default.
