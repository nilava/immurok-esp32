# immurok-esp32

An independent firmware that makes a **Seeed XIAO ESP32-S3 + ZW101 fingerprint sensor**
speak the [immurok](https://github.com/immurok) BLE protocol, so immurok's companion apps
drive it unmodified.

It stands on two projects:

- **[zimengxiong/tinytouch](https://github.com/zimengxiong/tinytouch)** (MIT) — the
  hardware. Same XIAO ESP32-S3, same ZW101 sensor, **same printed case**, which is
  redistributed here in [`hardware/case/`](hardware/case/). tinytouch is also where this
  build's first working ZW101 UART driver came from.
- **[immurok](https://github.com/immurok)** — the protocol and the companion apps this
  firmware talks to.

tinytouch's own firmware is a USB HID / PIV smart-card device. This one replaces that
entirely with a BLE implementation of immurok's protocol, on the same physical build.

Touch the sensor to unlock your Mac or Windows PC. Hold for two seconds to lock it. It
binds to two computers at once and hops between them on a dedicated fingerprint, and it
carries an on-device SSH key vault and TOTP vault that sign only after a fingerprint.

> ### ⚠️ Unaffiliated third-party project
>
> **This project is not affiliated with, endorsed by, supported by, or produced by
> immurok.** It is an independent reimplementation by an unrelated person, for different
> hardware than immurok sells.
>
> - immurok did not write this firmware and **cannot support it**. If something here
>   breaks, **it is my bug, not theirs** — open an issue on *this* repository. Please do
>   not file issues, feature requests or support questions on immurok's repositories, and
>   please do not contact them about this project.
> - **Buying immurok's hardware is not the same as using this**, and using this is not a
>   substitute for their product. If you want the polished, supported experience, buy
>   their device.
> - The name "immurok" is used here only to state *what protocol this speaks*, which is a
>   factual description of compatibility — not a claim of origin, endorsement or
>   partnership.
> - **No immurok firmware code is used.** Their firmware is BSL-licensed and targets
>   entirely different silicon. See [Licensing and provenance](#licensing-and-provenance).
>
> immurok were asked before this was published and were happy for it to exist. That is a
> courtesy they extended, not an endorsement of the code.

---

## Status

Working and in daily use, on one person's desk, on one build of the hardware. Pairing,
enrolment, matching, screen unlock, hold-to-lock, dual-host binding, host switching, the
SSH vault (verified against a real `ssh-add -L`) and the TOTP vault all function against
immurok's macOS app.

It has not been security-audited, has not been tested across ZW101 revisions, and has run
on exactly one device. Read [Security model](#security-model) before trusting it with
anything that matters.

## Hardware

Identical to a tinytouch build — if you have already built one, this firmware runs on it
as-is with no rewiring.

### Bill of materials

| Part | Used here | Notes |
|---|---|---|
| Microcontroller | Seeed Studio XIAO ESP32-S3 | Needs native USB and a hardware UART. Any ESP32-S3 board exposing those pins should work |
| Fingerprint sensor | ZW101-style UART sensor | Round capacitive sensor with an RGB "aura" ring, `0xEF01` packet protocol. Other sensors speaking the same protocol may work |
| Case | Printed top + bottom | [`hardware/case/`](hardware/case/), from tinytouch (MIT) |
| Wiring | 5 × silicone hookup wire | The sensor pigtail is short; see the case notes |
| Host | macOS (tested), Windows / Linux (untested) | Needs the matching immurok companion app |

The ESP32-S3 part sold as 8 MB flash is what this was built on, but the firmware targets a
4 MB layout so it fits either.

### Wiring

The ZW101 talks over **UART1 at 57600 baud, 8N1**.

| ZW101 wire | XIAO pin label | GPIO | Direction |
|---|---|---|---|
| TX | D7 | 44 | sensor → MCU (MCU RX) |
| RX | D6 | 43 | MCU → sensor (MCU TX) |
| IRQ / touch-out | D1 | 2 | sensor → MCU, **active high**, internal pull-down |
| VCC | 3V3 | — | 3.3 V only |
| GND | GND | — | |

```
   ZW101                         XIAO ESP32-S3
  ┌────────────┐                ┌───────────────┐
  │  TX  ──────┼────────────────┤ D7 / GPIO44   │  (MCU RX)
  │  RX  ──────┼────────────────┤ D6 / GPIO43   │  (MCU TX)
  │  IRQ ──────┼────────────────┤ D1 / GPIO2    │  (active high)
  │  VCC ──────┼────────────────┤ 3V3           │
  │  GND ──────┼────────────────┤ GND           │
  └────────────┘                └───────────────┘
```

Notes from building this:

- **TX goes to RX.** The sensor's transmit line lands on the MCU's receive pin, and vice
  versa. If you get it backwards the firmware recovers anyway — it tries both orientations
  at boot with a `VfyPwd` probe and keeps whichever one answers, logging which it chose.
- The IRQ pin can go to any free GPIO; change `FP_INT_PIN` in `main/fingerprint.c` if you
  move it. It is configured with an internal pull-down and read as active-high.
- **3.3 V only.** Do not feed the sensor 5 V.
- Check continuity between 3V3 and GND before first power-up.
- The sensor needs about 600 ms after power-on before it answers its first command; the
  firmware waits this out at boot.

Pin definitions live at the top of [`main/fingerprint.c`](main/fingerprint.c) if you need
to move anything.

## Flash a prebuilt binary (no ESP-IDF needed)

If you just want a working device and don't intend to modify the firmware, grab the
latest [**release**](https://github.com/nilava/immurok-esp32/releases) and flash the
merged image. You need Python and `esptool`, nothing else:

```bash
pip install esptool

# One file, flashed at offset 0 — contains bootloader + partition table + app.
esptool.py --chip esp32s3 write_flash 0x0 immurok-esp32-vX.Y.Z-merged.bin
```

Add `-p PORT` if it can't find the board (`/dev/cu.usbmodem101`, `/dev/ttyACM0`, `COM7` —
see the port table [below](#4-flash)). If flashing fails, hold **BOOT**, tap **RESET**,
release **BOOT**, and retry.

**Verify what you're flashing.** Each release ships a `SHA256SUMS` file:

```bash
shasum -a 256 -c SHA256SUMS
```

> **A prebuilt binary is a trust decision.** You are running a security device on a
> stranger's compiled artifact. The checksums prove the file matches what I uploaded —
> they prove nothing about what I put in it. If that matters to you, and for a
> fingerprint authenticator it reasonably might, **build from source instead** using the
> instructions below. The build is reproducible from a clean checkout with ESP-IDF v5.3.2.

To erase everything and start fresh (this destroys pairing keys, fingerprints and vault
contents): `esptool.py --chip esp32s3 erase_flash`

## Build from source

Written assuming you have never used ESP-IDF before. If you have, it is just
`idf.py set-target esp32s3 && idf.py flash monitor`.

### 1. Install ESP-IDF v5.3.2

ESP-IDF is Espressif's SDK — the compiler, the libraries and the `idf.py` tool. This
project is built and tested against **v5.3.2**; other 5.x releases will most likely work.

**macOS / Linux**

```bash
# Prerequisites: git, cmake, ninja, python3.
#   macOS:  brew install cmake ninja python3
#   Debian/Ubuntu: sudo apt install git wget flex bison gperf python3 python3-venv \
#                                   cmake ninja-build ccache libffi-dev libssl-dev dfu-util

mkdir -p ~/esp && cd ~/esp
git clone -b v5.3.2 --recursive https://github.com/espressif/esp-idf.git
cd ~/esp/esp-idf
./install.sh esp32s3
```

**Windows** — use the [ESP-IDF Windows Installer](https://dl.espressif.com/dl/esp-idf/),
pick v5.3.2, then use the "ESP-IDF PowerShell/CMD" shortcut it creates instead of running
`export.sh`.

### 2. Get the firmware

```bash
cd ~/esp
git clone https://github.com/nilava/immurok-esp32.git
cd immurok-esp32
```

### 3. Build

**Every new terminal needs the ESP-IDF environment loaded first.** This is the single most
common stumble — if `idf.py` is "command not found", you skipped this line:

```bash
source ~/esp/esp-idf/export.sh    # macOS/Linux, once per terminal session
idf.py set-target esp32s3         # only needed the first time
idf.py build
```

The first build takes several minutes and prints a lot. It ends with
`Project build complete.`

### 4. Flash

Plug the XIAO into USB and run:

```bash
idf.py flash monitor
```

`idf.py` usually finds the board on its own. To be explicit, pass the port with `-p`:

| OS | Find the port | Looks like |
|---|---|---|
| macOS | `ls /dev/cu.usbmodem*` | `/dev/cu.usbmodem101` |
| Linux | `ls /dev/ttyACM*` | `/dev/ttyACM0` |
| Windows | Device Manager → Ports (COM & LPT) | `COM7` |

```bash
idf.py -p /dev/cu.usbmodem101 flash monitor
```

`monitor` shows the device's serial output. **Press `Ctrl+]` to exit it** (not Ctrl+C).

### 5. First boot

You should see something like:

```
fp: sensor verify OK with tx=43 rx=44
fp: sensor init: 0 template(s) enrolled, index bitmap=0x00
imk_crypto: crypto init: unpaired
imk_service: advertising as immurok-tt (ok)
immurok: immurok-esp32 boot; console: d=download r=restart ...
```

`sensor verify OK` means the wiring is right. If you instead see
`sensor verify failed on both orientations`, the sensor is not answering — check the
3V3/GND connections first, then the two data wires.

The ring should settle to steady purple (or breathing red if no computer is paired yet).
Now continue to [Setup](#setup).

### Troubleshooting

- **Board doesn't appear as a serial port at all.** Try a different USB-C cable. Many
  cables are charge-only with no data lines, and this trips up more people than any other
  cause. A cable that charges your phone is not proof.
- **`Permission denied` on `/dev/ttyACM0` (Linux).** Add yourself to the serial group and
  log out and back in: `sudo usermod -a -G dialout $USER`
- **Flashing fails or the port vanishes mid-flash.** Put the board into download mode
  manually: hold **BOOT**, tap **RESET**, release **BOOT**, then re-run the flash command.
- **Once this firmware is already running**, you don't need the button dance — press `d`
  in the monitor to reboot straight into download mode.
- **`idf.py: command not found`.** You didn't `source ~/esp/esp-idf/export.sh` in this
  terminal. It has to be done in every new shell.

### Partition layout

`partitions.csv`: 64 KB NVS at `0x9000`, a single 3 MB app at `0x20000`. There is no OTA
slot — this firmware updates over USB. The NVS offset is deliberately kept stable across
versions, so reflashing preserves your pairing keys, enrolled fingerprints and vault
contents. `idf.py erase-flash` wipes all of that and puts you back to unpaired.

## Companion apps

This firmware is only half of the system. The host-side software is **immurok's**, and it
does the genuinely hard part — the PAM module, the Windows credential provider, the SSH
agent, the secret vault. Get it from them, not from me:

| Platform | Repository | Tested with this firmware? |
|---|---|---|
| macOS | [immurok/app-macos](https://github.com/immurok/app-macos) | **Yes** — this is what everything was developed against |
| Windows | [immurok/app-win](https://github.com/immurok/app-win) | Not tested. Same protocol, so expected to work — treat that as an expectation, not a result |
| Linux | [immurok/app-linux-rs](https://github.com/immurok/app-linux-rs) | Not tested. (Note: `app-linux` is archived; `app-linux-rs` is the current one) |
| AI agent skill | [immurok/imk-skill](https://github.com/immurok/imk-skill) | Not tested |

Their main project, docs and hardware:
[immurok/immurok](https://github.com/immurok/immurok) ·
[immurok/hardware](https://github.com/immurok/hardware) ·
[immurok/firmware](https://github.com/immurok/firmware) ·
[immurok.com](https://immurok.com)

Again: **support questions about those apps go to immurok; support questions about this
firmware come to me.** Please keep the two separate — it is unfair to land my bugs in
their inbox.

## Setup

1. Install immurok's companion app for your OS from the table above.
2. Flash the firmware and power the device.
3. In the app, **Pair**. The device advertises as `immurok-tt`. It will ask for a touch to
   confirm physical presence (immurok's reference hardware uses a button; this build uses
   a fingerprint touch instead).
4. **Add a fingerprint** in the app.
5. Optional: to bind a second computer, run the app there and pair. The device will ask
   you to verify with an already-enrolled finger, then touch again to confirm.
6. Optional: enrol the 6th slot as a **switch finger** to hop between the two computers.

To use the SSH vault, enable the SSH agent in the app, then `ssh-add -L` will list a key
that lives only on the device. Screen-lock requests (hold-to-lock) require the app's
opt-in "screen lock" setting to be turned on.

## Feature set

- ECDH P-256 pairing with HKDF-SHA256 key derivation; per-touch HMAC-SHA256 signatures
- Fingerprint unlock, `sudo` / PAM authentication via the companion app
- **Hold 2 seconds to lock** the connected computer
- **Dual-host**: two independent pairing keys, each bound to a host's BLE identity;
  a dedicated switch finger hands the device between them
- **Fingerprint gate**: enrolment, deletion, key signing and OTP all require verifying an
  enrolled finger first, with 3 attempts and a 25-second timeout
- **SSH vault**: 32 P-256 keys, generated on-device or imported; `KEY_SIGN` for the agent
- **TOTP vault**: 128 secrets, RFC 6238 codes computed on-device
- **API-secret vault**: 50 entries for the companion CLI

### Ring LED language

| Ring | Meaning |
|---|---|
| Steady purple | Ready |
| Breathing red | No computer reachable |
| Breathing purple | Reading your touch |
| Green | Recognised *(the sensor's own indicator — see quirks)* |
| Steady red | Not recognised |
| Breathing cyan | Verify an enrolled finger to proceed |
| Breathing blue | Enrol: place finger / switching hosts |
| Steady cyan | Enrol: lift finger |
| Steady blue | Lock request sent |

### Serial console

Type these in `idf.py monitor` (USB-Serial-JTAG, no extra adapter needed):

| Key | Action |
|---|---|
| `d` | Reboot into ROM download mode (no BOOT/RESET button dance) |
| `r` | Restart |
| `i` | Sensor info: template count, index bitmap, per-slot load probe |
| `w` | Wipe all fingerprint templates |
| `p` | Dump both host binding slots |
| `u` | Clear both host bindings (fingerprints untouched) |
| `c` | Sweep the LED colour palette |
| `s` / `S` | Passive / active BLE scan of nearby advertisers |

## Protocol compatibility

Implemented opcodes: `0x01` GET_STATUS, `0x02` GET_BATT_RAW, `0x10`/`0x11` ENROLL
START/CANCEL, `0x12` DELETE_FP, `0x13` FP_LIST, `0x22` FP_MATCH_ACK, `0x30`-`0x32`
PAIR_INIT/CONFIRM/STATUS, `0x33` AUTH_REQUEST, `0x37` GATE_CANCEL, `0x38` CHALLENGE,
`0x39` SLOT_STATUS, `0x3C` SLOT_CLEAR, `0x60`-`0x69` the keystore range.
Notifications: `0x21` signed match, `0x23` lock request.

**Not implemented:** immurok's OTA scheme. This firmware reports version `99.0.0` so the
companion app's update checker always reads "up to date" and never offers an image this
device could not apply. If you fork this, keep that in mind — a real version number will
prompt users to flash immurok firmware onto incompatible hardware.

## Security model

Please read this before relying on the device.

**What it protects against.** A remote attacker, or someone who picks up your unlocked
laptop. Each touch is signed with a per-host key established by ECDH, so a replayed or
forged match notification is rejected. SSH private keys never leave the device and are
masked from protocol reads; signing requires a live fingerprint.

**What it does not protect against.**

- **Physical possession of the device.** Flash encryption and NVS encryption are *off*.
  The ECDH shared keys, SSH private keys, TOTP secrets and API secrets are stored in
  plaintext NVS and can be read out with `esptool read_flash`. This was a deliberate
  trade for a personal build; it is the single biggest limitation and it makes the device
  unsuitable for a threat model that includes losing it.
- **Fingerprints are not secrets.** A capacitive sensor at this price point is not
  presentation-attack resistant.
- **No audit.** No third party has reviewed the crypto, the protocol implementation, or
  the memory safety of the parser.

**Design rule worth preserving if you extend this:** proximity, presence and any
similar signal may *remove* access but must never *grant* it. Anything a nearby device
broadcasts can be spoofed by any other nearby device.

## ZW101 quirks worth knowing

These cost real debugging time and are documented here so they cost you less. They were
established empirically on one unit and confirmed against the Hi-Link
"Fingerprint module user communication protocol" v1.1 datasheet where possible.

- **The ring LED command (`0x3C`) is `[function][start colour][end colour][cycles]`.**
  There is no speed byte. Colours are a 3-bit RGB mask (bit0 blue, bit1 green, bit2 red).
  Functions: 1 breathe, 2 flash, 3 steady on, 4 off, 5 fade in, 6 fade out.
- **Re-sending an identical aura command visibly re-blinks the ring**, so repaints must be
  deduplicated. "Holding" a colour by repainting it produces flicker rather than steadiness.
- **The module drives its own LED after a capture** — green on a successful match, a red
  blink per failed `Match` — and ignores `0x3C` while it does. It cannot be suppressed by
  any documented command or parameter; design around it.
- **The IRQ pin de-asserts when a capture completes**, even with the finger still down. It
  can detect the *start* of a touch but never that a finger is still held; poll the sensor
  with `GenImg` for that (`0x00` = finger present, `0x02` = none).
- **`Search` (0x04) confirm `0x09` means an authoritative "not found".** Trust it. Falling
  back to a per-slot `LoadChar`+`Match` sweep fires the module's red blink once per
  enrolled template.
- **Template page 0 is unusable on this unit** — invisible to the index table and matching
  at score ≈ 1. The firmware maps app slot *N* to sensor page *N+1* throughout.
- The sensor needs roughly 600 ms after power-on before its first command, and the UART
  needs draining to an idle line before each command when BLE is loading the CPU.

## Licensing and provenance

This firmware is original C written for the ESP-IDF. It contains **no code from immurok's
firmware**, which is under the Business Source License and targets a different MCU
(WCH CH592F) and a different sensor.

What it *was* built from:

- **[immurok/app-macos](https://github.com/immurok/app-macos)** (Apache-2.0) — read as the
  authoritative description of the wire protocol. The behaviours it expects are
  reimplemented here in C; no Swift was copied.
- **immurok's protocol documentation** — note that the repository carrying it is under the
  Business Source License 1.1. This project's position is that implementing a wire
  protocol for interoperability is not a derivative of the licensed work.

  **immurok were contacted before this repository was made public, and confirmed they are
  happy for it to be published**, on the understanding that it is unaffiliated and not a
  derivative of their BSL-licensed firmware. Thanks to them for the quick and generous
  reply.
- **[zimengxiong/tinytouch](https://github.com/zimengxiong/tinytouch)** (MIT) — the
  hardware design this build is a copy of, and the origin of the working ZW101 UART
  command sequences. The printed case in [`hardware/case/`](hardware/case/) is
  redistributed from it unmodified, under its MIT licence, with the original copyright
  notice retained in `hardware/case/LICENSE.tinytouch`. None of tinytouch's firmware C is
  used — this project's firmware was written from scratch for a different protocol.
- **[anildash/dashtouch](https://github.com/anildash/dashtouch)** (MIT) — its LED
  diagnostics informed early work on the aura command, though this hardware ultimately
  behaves differently and the datasheet settled the details.
- **[Gadgetbridge](https://gadgetbridge.org/internals/specifics/ultrahuman-protocol/)** —
  the Ultrahuman BLE naming convention, used only by the optional scan diagnostic.

If immurok would like anything changed about the framing, attribution, or this project's
existence at any point, please open an issue — that request will be honoured.

**This project's own code is released under the MIT License** (see `LICENSE`).

## Acknowledgements

**[zimengxiong/tinytouch](https://github.com/zimengxiong/tinytouch)** — the hardware
combination, the case, and the first ZW101 driver that proved this sensor could be made to
behave. This project is a different firmware on that same physical build, and would not
exist without it.

**[immurok](https://github.com/immurok)** — for a protocol clean enough to reimplement and
companion apps good enough to be worth reimplementing it for. The apps do the genuinely
hard part on the host side: the PAM module, the credential provider, the SSH agent.
