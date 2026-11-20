function Install-UnbihexPortable([string]$Package, [string]$Folder) {
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $files = @('wintun.dll', 'wintun-LICENSE.txt', 'Unbihex.exe')
    $work = Join-Path $Folder ('.unbihex-update-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($work) | Out-Null
    $applied = [Collections.Generic.List[string]]::new()
    $keepBackup = $false
    try {
        $zip = [IO.Compression.ZipFile]::OpenRead($Package)
        try {
            foreach ($file in $files) {
                $entry = $zip.GetEntry("Unbihex/$file")
                if ($null -eq $entry) { $entry = $zip.GetEntry($file) }
                if ($null -eq $entry -or $entry.Length -le 0 -or $entry.Length -gt 128MB) {
                    throw "Missing or invalid file in portable package ($file)"
                }
                # Only the distribution files are extracted, using these fixed names.
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $work $file), $false)
            }
        } finally {
            $zip.Dispose()
        }

        foreach ($file in $files) {
            $source = Join-Path $work $file
            $target = Join-Path $Folder $file
            if ([IO.File]::Exists($target)) {
                [IO.File]::Replace($source, $target, (Join-Path $work "$file.previous"))
            } else {
                [IO.File]::Move($source, $target)
            }
            $applied.Add($file)
        }
    } catch {
        for ($i = $applied.Count - 1; $i -ge 0; $i--) {
            $file = $applied[$i]
            $target = Join-Path $Folder $file
            $backup = Join-Path $work "$file.previous"
            try {
                if ([IO.File]::Exists($backup)) {
                    [IO.File]::Replace($backup, $target, (Join-Path $work "$file.failed"))
                } else {
                    [IO.File]::Delete($target)
                }
            } catch {
                $keepBackup = $true
            }
        }
        if ($keepBackup) { throw "Portable rollback failed. Previous files are in $work" }
        throw
    } finally {
        if (!$keepBackup) {
            try {
                foreach ($file in $files) {
                    foreach ($suffix in @('', '.previous', '.failed')) {
                        [IO.File]::Delete((Join-Path $work ($file + $suffix)))
                    }
                }
                [IO.Directory]::Delete($work)
            } catch {
                Write-Verbose $_
            }
        }
    }
}

function Invoke-UnbihexUpdate {
    $ErrorActionPreference = 'Stop'
    $profile = [IO.Path]::GetFullPath($env:UNBIHEX_UPDATE_PROFILE)
    $stage = [IO.Path]::GetFullPath($env:UNBIHEX_UPDATE_STAGE)
    $exe = [IO.Path]::GetFullPath($env:UNBIHEX_UPDATE_EXE)
    $folder = [IO.Path]::GetDirectoryName($exe)
    if ([IO.Path]::GetDirectoryName($stage) -ne $profile -or
        [IO.Path]::GetFileName($stage) -notlike 'unbihex-update-*' -or
        [IO.Path]::GetFileName($exe) -ne 'Unbihex.exe') {
        throw 'Invalid update paths'
    }
    $package = switch ($env:UNBIHEX_UPDATE_MODE) {
        'setup' { Join-Path $stage 'update.exe' }
        'portable' { Join-Path $stage 'update.zip' }
        default { throw 'Unknown update format' }
    }
    $notice = Join-Path $profile 'update-error.txt'
    $profileLock = $null
    $packageFile = $null
    $restart = $false
    try {
        $parentProcess = Get-Process -Id ([int]$env:UNBIHEX_UPDATE_PID) -ErrorAction SilentlyContinue
        if ($parentProcess -and !$parentProcess.WaitForExit(120000)) {
            throw 'Timed out waiting for Unbihex to exit'
        }
        $restart = $true
        $profileLock = [IO.File]::Open((Join-Path $profile 'client.lock'), 'Open', 'ReadWrite', 'ReadWrite')
        # Overlaps the exclusive lock the client takes on this file.
        $profileLock.Lock(0, 1)

        # Retain a read handle so the verified file cannot change before installation.
        $packageFile = [IO.File]::Open($package, 'Open', 'Read', 'Read')
        $sha = [Security.Cryptography.SHA256]::Create()
        try {
            $digest = [BitConverter]::ToString($sha.ComputeHash($packageFile)).Replace('-', '')
        } finally {
            $sha.Dispose()
        }
        if ($digest -ne $env:UNBIHEX_UPDATE_SHA256) {
            throw 'Update file changed after download'
        }

        if ($env:UNBIHEX_UPDATE_MODE -eq 'setup') {
            # NSIS requires /D at the end and accepts a path with spaces without quoting it.
            $install = Start-Process -FilePath $package -ArgumentList "/S /D=$folder" -Verb RunAs -WindowStyle Hidden -Wait -PassThru
            if ($install.ExitCode -ne 0) { throw "Installer exit code $($install.ExitCode)" }
        } else {
            Install-UnbihexPortable $package $folder
        }
    } catch {
        $message = 'Unbihex update failed. ' + $_.Exception.Message
        [IO.File]::WriteAllText($notice, $message)
    } finally {
        if ($null -ne $packageFile) { $packageFile.Dispose() }
        if ($null -ne $profileLock) { $profileLock.Dispose() }
        try {
            [IO.File]::Delete($package)
            [IO.Directory]::Delete($stage)
        } catch {
            Write-Verbose $_
        }
        if ($restart) {
            Start-Process -FilePath $exe -WorkingDirectory $folder
        }
    }
}
