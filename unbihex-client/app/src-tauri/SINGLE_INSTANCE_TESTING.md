# Windows single-instance regression checks

Related: https://github.com/crystalmasta/unbihex/issues/61

The Windows GUI uses session-local named kernel objects before opening client
data. The CLI and non-Windows targets are unchanged. A manual launch signals the
existing GUI; an autostart launch exits silently. The existing show_window path
restores a minimized window or recreates the window closed to the tray.

## Automated tests

From unbihex-client, on Windows with the Rust/MSVC build prerequisites:

```powershell
cargo test --locked -p unbihex-client --lib single_instance::tests
cargo check --locked -p unbihex-client
```

The tests cover competing launches, activation versus autostart, releasing the
guard and acquiring it again, and invalid restart-parent arguments.

## Manual checks (Windows 10 and 11)

1. Open the GUI repeatedly, including several near-simultaneous launches.
   Only one GUI process and one tray icon should remain.
2. Minimize the window and launch again. The existing window should be restored.
3. Close the window to the tray and launch again. One new window should appear
   in the original process; the current VPN connection should remain unchanged.
4. Repeat while connected in proxy and TUN modes. No second engine should start.
5. Launch with --autostart while already running. No window should be opened.
6. Quit from the tray, then launch again. Repeat after terminating the process.
   No stale instance lock should prevent startup.
7. Use the in-app restart-as-administrator command: accept UAC, then repeat with
   UAC cancelled. Acceptance should leave one elevated GUI after the old process
   exits; cancellation should retain the original instance and its lock.
8. Repeat the administrator restart used to apply autostart settings.
9. Run the primary elevated, then launch normally, and reverse the order.

## Boundaries

Objects use the default Windows ACL and the Local namespace (one logon session).
Windows may deny activation across integrity levels or deny foreground focus.
An access failure aborts the new GUI rather than allowing another VPN engine;
use the existing tray icon when Windows prevents foreground activation.
No IPC request can execute commands or initiate elevation.

The restart child waits up to 30 seconds for the parent process to exit, including
its route/proxy cleanup. A timeout or inaccessible parent aborts startup. The old
instance keeps its guard throughout the UAC prompt; it never opens an unlocked
gap if UAC is cancelled.

## Validation performed during implementation

A Python ctypes harness on Windows exercised the same kernel APIs across separate
processes: exclusion, activation, silent autostart, automatic event reset, and
reacquisition after handles close. Both Cargo TOML files parsed successfully.
The Rust tests, full app build, and interactive checks above were not run in the
implementation environment because Rust/MSVC were unavailable.
