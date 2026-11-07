# Device pictures: sources and licence

The pictures on the wiring screen. Each `<part>.svg` has a `<part>.json` beside it
with the connector positions, what each connector is for, and the same attribution
as below. The whole folder is under **CC BY-SA 3.0**
(https://creativecommons.org/licenses/by-sa/3.0/): the Adafruit parts are released
under it, and the parts drawn for MedCEA use it too, so the folder has one licence.

Imported parts come from `edge/tools/import-fritzing.py` (run with `python3 -I`
on the downloaded `.fzpz`); re-import rather than editing them by hand.

| File | Source | URL | Commit | File in source | Author | Licence | Changes |
|---|---|---|---|---|---|---|---|
| `adafruit-tca9548a.svg`/`.json` | Adafruit Fritzing-Library, part "Adafruit TCA9548A" | https://github.com/adafruit/Fritzing-Library | c7bbe2d58a78ebc7b3499351c0f77356cd701c96 | `parts/Adafruit TCA9548A.fzpz` | ladyada (Adafruit Industries) | CC BY-SA 3.0 | Breadboard view only; metadata, ids and editor attributes removed, numbers rounded, scripts and external references stripped; connector centres computed by import-fritzing.py |
| `adafruit-sht4x.svg`/`.json` | Adafruit Fritzing-Library, part "Adafruit SHT4x" | https://github.com/adafruit/Fritzing-Library | c7bbe2d58a78ebc7b3499351c0f77356cd701c96 | `parts/Adafruit SHT4x.fzpz` | kattni (Adafruit Industries) | CC BY-SA 3.0 | As above |
| `adafruit-scd30.svg`/`.json` | Adafruit Fritzing-Library, part "Adafruit SCD30" | https://github.com/adafruit/Fritzing-Library | c7bbe2d58a78ebc7b3499351c0f77356cd701c96 | `parts/Adafruit SCD30.fzpz` | ladyada (Adafruit Industries) | CC BY-SA 3.0 | As above |
| `esp32-s3-devkitc-1.svg`/`.json` | Drawn for MedCEA from Espressif's ESP32-S3-DevKitC-1 v1.1 user guide (header blocks J1/J3) | https://docs.espressif.com/projects/esp-dev-kits/en/latest/esp32s3/esp32-s3-devkitc-1/user_guide_v1.1.html | - | - | MedCEA | CC BY-SA 3.0 (MedCEA) | Original drawing |
| `dfrobot-sen0562.svg`/`.json` | Drawn for MedCEA from DFRobot's SEN0562 wiki (pinout: red VCC, blue GND, yellow SCL, green SDA) | https://wiki.dfrobot.com/sen0562/ | - | - | MedCEA | CC BY-SA 3.0 (MedCEA) | Original drawing |

The Adafruit Fritzing-Library README: "Released under CC Attribution Share-Alike".
A new part adds its row here and its `attribution` block in the json.
