# Pinned MicroPython images

`.bin` files are gitignored — they are multi-megabyte binaries published by
upstream. What lives in git is `SHA256SUMS` plus this table: the exact file name
and SHA-256 each board family was flashed with, so a provisioning record can be
checked against a known image rather than a hope.

**You do not need to populate this directory by hand.** `flash-device.sh` reads
the chip family off the silicon, lists what is already here for that board,
asks micropython.org what it publishes, and downloads on request — hashing
whatever it fetches into `SHA256SUMS`.

| Board family | Upstream board page | File flashed | SHA-256 | Offset |
|---|---|---|---|---|
| ESP32-S3 (UNIT02, cameras) | <https://micropython.org/download/ESP32_GENERIC_S3/> | _recorded in SHA256SUMS_ | | `0x0` |
| ESP32-WROOM-32 (UNIT01) | <https://micropython.org/download/ESP32_GENERIC/> | _recorded in SHA256SUMS_ | | `0x1000` |

## There is no upstream API

Worth writing down, because it is the first thing anyone automating this looks
for. As of 2026-08-30:

- `https://micropython.org/api/v2/boards` and `.../downloads` — **404**.
- `https://micropython.org/download/<BOARD>/?json` — returns the same HTML as
  without the parameter. There is no JSON representation.
- No `.sha256` sidecar next to a firmware file — `…-v1.29.0.bin.sha256` is a 404.
  The hash in `SHA256SUMS` is therefore computed locally, from the bytes that
  were actually written to the board.
- The board index at `/download/` is filtered client-side, so it carries no
  static list of board names to enumerate.

What does work is that the download page is server-rendered and the link format
is strictly regular, so scraping it is reliable rather than fragile:

```
/resources/firmware/ESP32_GENERIC_S3-20260824-v1.29.0.bin
/resources/firmware/ESP32_GENERIC_S3-SPIRAM_OCT-20260824-v1.29.0.bin
/resources/firmware/ESP32_GENERIC_S3-20260827-v1.30.0-preview.8.gf668077be2.bin
                    └─ board ──────┘ └variant┘ └ date ┘ └ ver ┘ └── preview ──┘
```

`edge/src/host/list_firmware.py` parses exactly that. Run it directly to see
what upstream has:

```bash
python3 edge/src/host/list_firmware.py --board ESP32_GENERIC_S3 --limit 5
python3 edge/src/host/list_firmware.py --board ESP32_GENERIC --newest-per-variant
python3 edge/src/host/list_firmware.py --board ESP32_GENERIC_S3 --include-preview
```

It takes `--html-file` so the parser can be tested against a saved page with no
network.

## Preview builds sort newer than stable

This is the trap in "just take the latest". Preview builds carry a **later date**
than the newest stable release:

```
ESP32_GENERIC_S3-20260824-v1.29.0.bin                          <- newest stable
ESP32_GENERIC_S3-20260827-v1.30.0-preview.8.gf668077be2.bin    <- newer by date
```

So previews must be filtered out *before* sorting by date, or every run offers a
nightly. They are excluded by default and only appear under `--preview`.

## Which variant

The generic build is the right default. Reach for a specific variant only for a
reason you can name:

- **`SPIRAM_OCT`** — boards with octal PSRAM. Wrong on a board without it: the
  image boots and then fails in ways that look like flaky hardware.
- **`FLASH_4M`** — 4 MB parts. The default S3 build assumes 8 MB. Note this
  variant lags the others upstream (v1.25.0 while the generic build is at
  v1.29.0), so picking it means accepting an older MicroPython.
- **`SPIRAM`, `UNICORE`, `D2WD`, `OTA`** — classic ESP32 only.
- **Vendor builds** — the OV2640 camera boards need a build with the camera
  driver compiled in; the generic image has no `camera` module and never will.
  Keep that `.bin` here too, named for its vendor and version, and add its hash
  to `SHA256SUMS` by hand.

## Offsets are not interchangeable

ESP32-S3, C3 and C6 take the image at `0x0`. Classic ESP32 and S2 take it at
`0x1000`, because the first 4 KB holds the bootloader on those parts.
`flash-device.sh` reads the chip family off the silicon and picks the offset
itself — the value is never taken from the file name, because a renamed file
would then brick the board silently. Flashing at the wrong offset writes
successfully and produces a board that boot-loops with no useful error.
