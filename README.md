# nfc-ltocm-go

A Go tool for reading and parsing **LTO Cartridge Memory (LTO-CM)** tags via NFC. It talks to the ISO 14443A chip embedded in LTO tape cartridges, dumps the full 8 kB memory, and decodes every ECMA-319 page into a human-readable report or structured JSON.

This is a Go rewrite and combination of [nfc-ltocm](https://github.com/philpem/nfc-ltocm) and `ltocm` by Phil Pemberton. Licence: 2-clause BSD (same as original).

---

## Features

- Reads all 127, 255, or 511 LTO-CM blocks (auto-detected from REQUEST STANDARD response)
- Decodes all standard ECMA-319 protected and unprotected pages
- Decodes embedded MAM (Medium Auxiliary Memory) attributes
- Human-readable text output **or** structured JSON (`-json`)
- Optional raw binary dump (`-o file.bin`) for offline analysis or archival
- Verbose mode (`-v`) that includes per-page hex dumps
- Full TapeAlert flag decoding (68 flags)
- Detects LTFS volume UUIDs and barcode labels from the Application Specific page

---

## Pages decoded

### Protected pages

| Page | Content |
|---|---|
| `0x000` | CM Manufacturer Info — chip serial, capacity, write-inhibit |
| `0x001` | Cartridge Manufacturer Info — make, serial, type, tape length/thickness, speed |
| `0x002` | Media Manufacturer Info — servowriter, lot, date |
| `0x101` | Initialisation Data — formatting drive, LP positions |

### Unprotected pages

| Page | Content |
|---|---|
| `0x102` | Tape Write Pass (8 passes) |
| `0x103` | Tape Directory — active wraps, FID write pass |
| `0x104` | EOD Information — thread count, physical position, record/filemark counts |
| `0x105` | Cartridge Status & TapeAlert flags |
| `0x106` | Mechanism Related |
| `0x107` | Suspended Append Writes |
| `0x108–0x10B` | Usage Information slots 0–3 (per-drive statistics) |
| `0x10C–0x10E` | Extended drive statistics (raw) |
| `0x200` | Application Specific — MAM001 format ID, LTFS volume UUID |
| `0x201–0x2FF` | Host Specific pages (raw) |

---

## Requirements

- Go 1.20+
- [libnfc](https://github.com/nfc-tools/libnfc) with development headers
- A compatible NFC reader — tested with **ACS ACR122U**

### Install libnfc

```bash
# Debian / Ubuntu
sudo apt install libnfc-dev libnfc-bin

# Fedora / RHEL
sudo dnf install libnfc-devel

# macOS (Homebrew)
brew install libnfc
```

---

## Build

```bash
go build -o nfc-ltocm-go .
```

CGo is required; the build links against `libnfc` via `pkg-config`.

---

## Usage

Place an LTO cartridge on the NFC reader, then run:

```
./nfc-ltocm-go [flags]
```

| Flag | Description |
|---|---|
| `-o <file>` | Save raw 8 kB CM binary dump to `file` |
| `-json` | Output parsed data as JSON instead of text |
| `-v` | Include hex dumps of each page in the text output |

### Examples

```bash
# Read tag and print report to stdout
./nfc-ltocm-go

# Also save raw binary for later analysis
./nfc-ltocm-go -o cartridge.bin

# Machine-readable output (pipe to jq, etc.)
./nfc-ltocm-go -json | jq '.unprotected_pages.usage_info'

# Verbose: include hex dump of every page
./nfc-ltocm-go -v
```

---

## Sample output

```
NFC reader: ACS / ACR122U PICC Interface opened
Found LTO-CM tag with s/n 35:CD:2A:23:F1
Read 8160 bytes from tag.

LTO Cartridge Memory [35:CD:2A:23:F1]

────────────────────────────────────────────────────────────
CM MANUFACTURER INFO  (0x0000)
────────────────────────────────────────────────────────────
  CM Serial Number         : 35CD2A23F1
  Chip Capacity            : 64kbit

────────────────────────────────────────────────────────────
CARTRIDGE MANUFACTURER INFO  (page 0x001)
────────────────────────────────────────────────────────────
  Manufacturer             : IBM
  Serial Number            : ER6JT8D405
  Cartridge Type           : LTO-5 (0x0010)
  Date of Mfg              : 20130716
  Tape Length              : 846 m  (3384 raw × 0.25)
  Tape Thickness           : 6554 nm  (6.554 µm)
  Max Media Speed          : 12336 mm/s
  License Code             : U107

────────────────────────────────────────────────────────────
USAGE INFORMATION  (pages 0x108–0x10B, slots 0–3)
────────────────────────────────────────────────────────────
  Slot 2  (page 0x10A)  Drive: IBM  ID: 0000078ABD
    Thread Count                    : 631
    Datasets Written                : 1624478
    Datasets Read                   : 1760761
    Recovered Write Errors          : 24
    Recovered Read Errors           : 35
    Unrecovered Write Errors        : 0
    Unrecovered Read Errors         : 0
    Write Servo Errors              : 21
    Beginning-of-Medium Passes      : 1762
    Middle-of-Tape Passes           : 1653

────────────────────────────────────────────────────────────
SUMMARY
────────────────────────────────────────────────────────────
  Cartridge : IBM  ER6JT8D405
  Type      : LTO-5
  Formatted : true
  Media Mfg : FUJIFILM
  Threads   : 631
  Chip      : 64kbit
```

---

## References

- [ECMA-319](https://www.ecma-international.org/publications/files/ECMA-ST/ECMA-319.pdf) — LTO Cartridge Memory specification
- [nfc-ltocm](https://github.com/philpem/nfc-ltocm) — original C implementation by Phil Pemberton
- [libnfc](https://github.com/nfc-tools/libnfc) — NFC library

---

## Licence

2-clause BSD — same as the original `nfc-ltocm` project.
