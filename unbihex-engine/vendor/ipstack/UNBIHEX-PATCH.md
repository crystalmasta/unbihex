# ipstack 1.0.1 — Unbihex patch

This is ipstack 1.0.1 from crates.io (the latest release) with five changes. The build
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

3. **A bounded read queue.** Stock ipstack moved every in-order segment from the app
   into an unbounded channel and acknowledged it with a full window, so an app uploading
   faster than the stream was read filled memory without limit. Now the bytes in that
   channel (`Tcb::unread`, `add_unread` / `release_unread` in `src/stream/tcb.rs`) count
   against `read_buffer_size`, and the advertised window closes to 0 when it is full (the
   old MTU floor on the window is gone). When the reader frees the buffer past half,
   `IpStackTcpStream::consumed` (`src/stream/tcp.rs`) sends the app a pure ACK with the
   reopened window: below half the last advertised window may have stalled it, above
   half it never does.

4. **Retransmission on a timer.** Stock ipstack checked for timed-out segments only when
   a packet arrived from the app, so a lost tail (or a lost last ACK) left both sides
   waiting for good; a segment out of retransmissions was dropped and the stream went on
   with a hole. Now the stream task also sleeps until the earliest in-flight segment is
   due (`Tcb::next_retransmit_at`; `poll_write` wakes it through `rto_notify` when the
   first segment goes in flight) and resends then (`retransmit_timed_out`). A segment
   still unacknowledged after `max_retransmit_count` resends resets the stream
   (`Tcb::retransmits_exhausted`, RST).

5. **One segment copied per write.** `poll_write` (`src/stream/tcp.rs`) copied the whole
   buffer it was given (64 KiB from the relay) for every segment and truncated the copy
   to one segment, keeping its capacity: 48 times the bytes copied, and as much memory
   for every segment waiting in the device queue. Now it copies at most one MTU. On the
   Windows bench this took one download through the TUN from 136 to 155 MB/s and the
   client's peak with 64 parallel downloads from 152 to 85 MB.

To move to a new ipstack version: check which of these upstream has fixed, copy the new
crate source here, reapply what is still needed, keep the version in
`unbihex-engine/Cargo.toml` in step, and run the engine tests
(`inbound::tun::tests`: `tcp_window_scale_and_non_blocking_drop` covers the first two
changes, `unread_data_closes_the_window_and_reading_reopens_it` the third,
`unacknowledged_tail_is_resent_then_reset` the fourth). The Windows bench
(64 parallel downloads through the TUN) found the fourth and measures the fifth.

Licensed like ipstack itself: Apache-2.0 (see LICENSE here).
