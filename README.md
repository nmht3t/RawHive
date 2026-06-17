# RawHive

RawHive is a Cobalt Strike BOF for pulling selected Windows registry hives directly from a raw NTFS volume. It skips the normal file APIs, walks NTFS metadata to find the target file records, and copies the bytes straight from disk.

It currently looks for:

- `C:\Windows\System32\config\SAM`
- `C:\Windows\System32\config\SYSTEM`
- `C:\Windows\System32\config\SECURITY`
- `C:\Windows\NTDS\ntds.dit`, if the host is a domain controller

By default it reads from `C:`, but you can point it at another local drive letter.

## How it works

1. Opens the selected local volume, for example `\\.\C:`.
2. Reads the NTFS boot sector and finds `$MFT`.
3. Walks directory indexes for `Windows`, `System32`, `config`, and the target files.
4. Falls back to a bounded MFT scan if the index lookup misses something.
5. Reads the target file data from resident data or cluster runlists.
6. Writes the recovered bytes to the output directory as `.tmp` files.

## Requirements

- 64-bit Beacon running as local admin or SYSTEM.
- `x86_64-w64-mingw32-gcc` and `make` for building.

## Build

```sh
make
```

That builds:

```text
dist/rawhive.x64.o
```

`rawhive.cna` loads the object from `dist/`, so rebuild after changing `rawhive.c`.

## Usage

```text
rawhive C:\Windows\Temp
```

Read `C:` explicitly:

```text
rawhive C C:\Windows\Temp
```

Read `D:` and write the output to `C:\Temp`:

```text
rawhive d C:\Temp
```

The volume can be written as `C`, `c`, or `C:`. The output directory must already exist.

## Output


```text
<host>_<timestamp>_sam.tmp
<host>_<timestamp>_system.tmp
<host>_<timestamp>_security.tmp
<host>_<timestamp>_ntds.tmp
```

`ntds.tmp` is written only if `C:\Windows\NTDS\ntds.dit` exists on the selected volume and RawHive can read it.

## Notes

- The fallback MFT scan is capped at 500,000 records.
- Runlists are capped at 128 extents. If a file is too fragmented, it fails instead of pretending a partial file is complete.
- The parser rejects malformed or unsupported NTFS structures instead of continuing with unsafe offsets.
- A file is only reported as extracted when the full expected data size is written.

## Troubleshooting

`outdir does not exist`

The directory you passed is missing on the target, or it is not a directory.

`open \\.\C: failed`

The Beacon probably does not have enough privilege, or raw volume access is blocked.

`not NTFS`

The selected volume does not appear to be NTFS.

`$mft runlist malformed` or `unsupported NTFS geometry`

The volume layout is unsupported or damaged

`output path too long`

Use a shorter output directory path.

## Proof of concept

![RawHive proof of concept](img.png)
