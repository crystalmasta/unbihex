import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const helper = fileURLToPath(new URL("../../app/src-tauri/src/windows-update.ps1", import.meta.url));
const windowsOnly = { skip: process.platform !== "win32" };
const script = `$ErrorActionPreference = 'Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:UNBIHEX_TEST_HELPER)))
$folder = Join-Path $env:UNBIHEX_TEST_ROOT 'Install Path'
$profile = Join-Path $env:UNBIHEX_TEST_ROOT 'profile'
$stage = Join-Path $profile 'unbihex-update-fixture'
$exe = Join-Path $folder 'Unbihex.exe'
$dll = Join-Path $folder 'wintun.dll'
$license = Join-Path $folder 'wintun-LICENSE.txt'
$lock = Join-Path $profile 'client.lock'
$note = Join-Path $profile 'update-error.txt'
[IO.Directory]::CreateDirectory($folder) | Out-Null
[IO.Directory]::CreateDirectory($stage) | Out-Null
[IO.File]::WriteAllText($exe, 'old executable')
[IO.File]::WriteAllText($dll, 'old library')
[IO.File]::WriteAllText($license, 'old license')
[IO.File]::WriteAllText($lock, '')
[IO.File]::WriteAllText((Join-Path $folder 'profile.txt'), 'user data')
$scenario = $env:UNBIHEX_TEST_SCENARIO
$setup = $scenario -eq 'setup'
if ($setup) {
    $package = Join-Path $stage 'update.exe'
    [IO.File]::WriteAllText($package, 'installer fixture')
} else {
    $package = Join-Path $stage 'update.zip'
    $source = Join-Path $env:UNBIHEX_TEST_ROOT 'fixture'
    $bundle = Join-Path $source 'Unbihex'
    [IO.Directory]::CreateDirectory($bundle) | Out-Null
    [IO.File]::WriteAllText((Join-Path $bundle 'Unbihex.exe'), 'new executable')
    [IO.File]::WriteAllText((Join-Path $bundle 'wintun.dll'), 'new library')
    [IO.File]::WriteAllText((Join-Path $bundle 'wintun-LICENSE.txt'), 'new license')
    [IO.File]::WriteAllText((Join-Path $bundle 'profile.txt'), 'ignore this')
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($package, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in [IO.Directory]::GetFiles($bundle)) {
            $name = [IO.Path]::GetFileName($file)
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $file, "Unbihex/$name") | Out-Null
        }
    } finally {
        $archive.Dispose()
    }
}
$env:UNBIHEX_UPDATE_STAGE = $stage
$env:UNBIHEX_UPDATE_PROFILE = $profile
$env:UNBIHEX_UPDATE_EXE = $exe
$env:UNBIHEX_UPDATE_PID = '123'
$env:UNBIHEX_UPDATE_MODE = if ($setup) { 'setup' } else { 'portable' }
$hasher = [Security.Cryptography.SHA256]::Create()
try {
    $env:UNBIHEX_UPDATE_SHA256 = if ($scenario -eq 'wrong hash') {
        'invalid'
    } else {
        [BitConverter]::ToString($hasher.ComputeHash([IO.File]::ReadAllBytes($package))).Replace('-', '')
    }
} finally {
    $hasher.Dispose()
}

function Get-Process {
    [CmdletBinding()] param([int]$Id)
    # The app has already exited. No real process is inspected or launched by the test.
}
$script:installed = 0
$script:reopened = 0
function Start-Process {
    param($FilePath, $ArgumentList, $Verb, $WindowStyle, [switch]$Wait, [switch]$PassThru, $WorkingDirectory)
    if ($FilePath -eq $package) {
        if ($Verb -ne 'RunAs' -or !$Wait -or !$PassThru -or $WindowStyle -ne 'Hidden' -or $ArgumentList -ne "/S /D=$folder") {
            throw 'Wrong NSIS arguments'
        }
        $script:installed++
        return @{ ExitCode = 0 }
    }
    if ($FilePath -ne $exe -or $WorkingDirectory -ne $folder) { throw 'Wrong restart arguments' }
    $check = [IO.File]::Open($lock, 'Open', 'ReadWrite', 'ReadWrite')
    try { $check.Lock(0, 1) } finally { $check.Dispose() }
    $script:reopened++
}
$handle = $null
try {
    if ($scenario -eq 'locked exe') { $handle = [IO.File]::Open($exe, 'Open', 'Read', 'Read') }
    Invoke-UnbihexUpdate
} finally {
    if ($null -ne $handle) { $handle.Dispose() }
}
if ($script:reopened -ne 1 -or [IO.Directory]::Exists($stage)) { throw 'Update did not finalize' }
if ($scenario -in @('portable', 'setup') -and [IO.File]::Exists($note)) { throw [IO.File]::ReadAllText($note) }
if ([IO.File]::ReadAllText((Join-Path $folder 'profile.txt')) -ne 'user data') { throw 'User file changed' }
if ($setup -and $script:installed -ne 1) { throw 'Setup not launched' }
$expected = if ($scenario -eq 'portable') { 'new' } else { 'old' }
if ([IO.File]::ReadAllText($exe) -ne "$expected executable" -or
    [IO.File]::ReadAllText($dll) -ne "$expected library" -or
    [IO.File]::ReadAllText($license) -ne "$expected license") {
    throw 'Distribution files are inconsistent'
}
if ([IO.File]::Exists($note) -ne ($scenario -in @('locked exe', 'wrong hash'))) {
    throw 'Wrong failure status'
}
`;

for (const scenario of ["portable", "locked exe", "wrong hash", "setup"]) {
  test("Windows update with " + scenario, windowsOnly, (t) => {
    const root = mkdtempSync(join(tmpdir(), "unbihex-updater-test-"));
    t.after(() => rmSync(root, { recursive: true, force: true }));
    const powershell = join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const encoded = Buffer.from(script, "utf16le").toString("base64");
    const result = spawnSync(powershell, ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded], {
      env: {
        ...process.env,
        UNBIHEX_TEST_ROOT: root,
        UNBIHEX_TEST_HELPER: helper,
        UNBIHEX_TEST_SCENARIO: scenario,
      },
      encoding: "utf8",
      windowsHide: true,
      timeout: 15_000,
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stdout + result.stderr);
  });
}
