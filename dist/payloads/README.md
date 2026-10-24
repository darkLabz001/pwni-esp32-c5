# PWNI BLE HID payloads

These are **benign examples**. They open a text editor and type a test string.
There are no credential stealers, downloaders, or destructive commands here.

Copy any `.txt` file to `/sdcard/payloads/` on the device (or upload it from
**Attacks → BLE HID keyboard** in the dashboard). Filenames use letters,
digits, `.`, `_`, and `-` and must end in `.txt`. HID mode is off after every
boot and requires the runtime authorization phrase before it can start.

## Syntax

| Line | Meaning |
|---|---|
| `REM comment` | Ignored |
| `DELAY 500` | Wait 500 ms |
| `DEFAULTDELAY 20` | Delay after each key (default 0) |
| `STRING text` | Type `text` in the US layout |
| `STRINGLN text` | Type `text` then press Enter |
| Plain line | A line that is not a command is typed as text |
| `ENTER`, `TAB`, `ESC`, `SPACE`, `BACKSPACE`, `DELETE` | Press one key |
| `UP`, `DOWN`, `LEFT`, `RIGHT`, `HOME`, `END`, `PAGEUP`, `PAGEDOWN` | Navigation keys |
| `F1`–`F12`, `CAPSLOCK`, `PRINTSCREEN`, `SCROLLLOCK`, `PAUSE`, `NUMLOCK` | Function keys |
| `GUI r`, `CTRL ALT t`, `CTRL SHIFT ESC`, `ALT F4` | Modifier + key combos |
| `CTRL+ALT+DELETE` | Same as spaces; `+` is accepted |
| `GUI`, `CTRL`, `ALT`, `SHIFT` | Press and release the modifier alone |

Modifiers: `CTRL`, `SHIFT`, `ALT`, `GUI` (`WIN`/`CMD`), plus `RCTRL`,
`RSHIFT`, `RALT`, `RGUI`. Text is US QWERTY only; non-ASCII bytes are skipped.

## Safety

Only run HID payloads against machines you own or have explicit written
permission to test. The device does not store host addresses, typed text, or
payload output. HID mode pauses the passive BLE scanner and resumes it when
stopped.
