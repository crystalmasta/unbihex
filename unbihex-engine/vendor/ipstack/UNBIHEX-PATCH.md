# ipstack 1.0.1 — Unbihex patch

This is ipstack 1.0.1 from crates.io (the latest release) with two changes. The build
script, examples and dev-dependencies are dropped: the build script only copied
`wintun.dll` for the examples.

Changes (search for "Unbihex patch"):

1. **TCP window scaling (RFC 7323).** Stock ipstack keeps windows in 16 bits and never
   offers the Window Scale option, so neither side can open more than 64 KiB, whatever
   `read_buffer_size` and `max_unacked_bytes` say. Now, when the app's SYN carries the
   option:
   - `src/stream/tcb.rs` — `send_window` is in bytes (`u32`), windows from the app are
     shifted by its scale (`scale_send_window`); our own shift is the smallest that fits
     `read_buffer_size` into 16 bits (`enable_window_scale`); `get_recv_window` shifts
     the advertised window, except in a SYN.
   - `src/stream/tcp.rs` — `IpStackTcpStream::new` reads the option from the SYN;
     `write_packet_to_device` / `create_raw_packet` add `NOP, WindowScale(shift)` to the
     SYN-ACK.
   Without the option in the SYN everything works as before.

2. **Non-blocking stream drop.** `Drop for IpStackTcpStream` (`src/stream/tcp.rs`)
   signalled its task and waited for it with `block_in_place` + `block_on`: every closed
   stream took a runtime worker out of service while it waited, and on a current-thread
   runtime it panicked. Now it only sends the exit signal (`try_send`) and the task ends
   on its own.

To move to a new ipstack version: check whether upstream fixed either point, copy the new
crate source here, reapply what is still needed, keep the version in
`unbihex-engine/Cargo.toml` in step, and run the engine tests
(`inbound::tun::tests::tcp_window_scale_and_non_blocking_drop` covers both changes).

Licensed like ipstack itself: Apache-2.0 (see LICENSE here).
