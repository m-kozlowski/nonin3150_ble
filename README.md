# Nonin WristOx2 3150 Tool

Command-line tool for configuring and reading data from Nonin WristOx2 3150 pulse oximeters. Supports both Bluetooth LE (3150 BLE) and Bluetooth Classic/SPP (3150 Classic) variants.

## Requirements

- Python 3.10+
- Bluetooth adapter (LE or Classic depending on device variant)
- [bleak](https://github.com/hbldh/bleak) for BLE variant
- [pyserial](https://github.com/pyserial/pyserial) for Classic variant (optional, only needed with --port)

Tested on Linux (Ubuntu/WSL2). BLE should work on Windows and macOS via bleak. Classic uses Python's built-in AF_BLUETOOTH socket (Linux) or pyserial for explicit port paths.

## Quick Start (BLE)

1. Insert batteries into the oximeter. You have 2 minutes to pair.

2. Find your device:
   ```
   python3 nonin_cli.py scan
   ```
   Press Ctrl+C when you see your device. Note the MAC address.

3. Read the current configuration:
   ```
   python3 nonin_cli.py config 08:6B:D7:13:01:E8 get-config
   ```
   First connection will pair automatically.

4. Set the device clock (so stored records have correct timestamps):
   ```
   python3 nonin_cli.py config 08:6B:D7:13:01:E8 set-datetime
   ```

5. Stream live readings:
   ```
   python3 nonin_cli.py stream 08:6B:D7:13:01:E8
   ```

## Quick Start (Classic/SPP)

1. Pair via bluetoothctl:
   ```
   bluetoothctl pair 00:1C:05:XX:XX:XX
   ```
   Enter the 6-digit PIN from the back of the device when prompted.

2. Read configuration:
   ```
   python3 nonin_cli.py --serial config 00:1C:05:XX:XX:XX get-config
   ```

3. Stream at 1Hz:
   ```
   python3 nonin_cli.py --serial stream 00:1C:05:XX:XX:XX --df df8
   ```

## Examples

### BLE streaming
```
python3 nonin_cli.py stream ADDR --csv -o readings.csv
python3 nonin_cli.py stream ADDR --streams all
python3 nonin_cli.py stream ADDR --format '{ts} SpO2={spo2} HR={pulse_rate}'
```

### Classic/SPP streaming
```
python3 nonin_cli.py --serial stream ADDR --df df8            # 1 Hz
python3 nonin_cli.py --serial stream ADDR --df df2            # 75 Hz with waveform
python3 nonin_cli.py --serial stream ADDR --df df2 --csv -o wave.csv
```

### Download stored sessions
```
python3 nonin_cli.py download ADDR                            # all sessions (BLE)
python3 nonin_cli.py download ADDR --first 3                  # 3 most recent
python3 nonin_cli.py download ADDR --after '2026-03-30 12:00' # by date
python3 nonin_cli.py download ADDR --csv -o sessions.csv      # as CSV
python3 nonin_cli.py --serial download ADDR --first 3         # Classic variant
```

### Configuration
```
python3 nonin_cli.py config ADDR set-datetime
python3 nonin_cli.py config ADDR set-activation bluetooth
python3 nonin_cli.py config ADDR set-storage-rate 1s
python3 nonin_cli.py config ADDR --raw get-config             # scripting output
python3 nonin_cli.py config --help                            # full docs
```

## Commands

| Command | Description |
|---------|-------------|
| `scan` | Find Nonin devices (BLE continuous scan, or `--serial` for serial ports) |
| `stream <addr>` | Stream live readings |
| `download <addr>` | Download stored sessions from device memory |
| `config <addr> ...` | Read/write device configuration |

Add `--serial` before any command to use Classic/SPP instead of BLE.

## Streaming Data Formats

### BLE streams (--streams)

| Stream | Data | Rate |
|--------|------|------|
| `oximetry` | SpO2, pulse rate, PAI, battery | 1/s |
| `df20` | Pulse interval timing | per pulse |
| `df22` | Raw PPG waveform (25 samples) | 3/s |
| `df23` | Device status, errors, battery % | 1/s |
| `all` | All of the above | |

### Classic/SPP data formats (--df)

| Format | Data | Rate |
|--------|------|------|
| `df2` | SpO2, PR, 8-bit compressed waveform | 75 Hz |
| `df7` | SpO2, PR, 16-bit full-resolution waveform | 75 Hz |
| `df8` | SpO2, PR | 1 Hz |
| `df13` | SpO2, PR (SmartPoint spot-check) | per measurement |

## Memory Download

The device stores SpO2 and pulse rate at a configurable interval (1s/2s/4s)
with capacity for up to ~1097 hours at 4s rate. Sessions are stored when the
device is on and measuring.

Download filters (can be combined):
- `--first N` - only the N most recent sessions (cancels early)
- `--skip N` - skip the N newest sessions
- `--after TIME` - sessions starting at or after TIME (cancels early)
- `--before TIME` - sessions starting before TIME

Output formats:
- Default: session summary with sample count, averages, min/max
- `--csv` - one row per sample with computed timestamps
- `--raw` - key=value headers + raw spo2,pr values

Note: timestamps depend on the device clock. Set it with
`config <addr> set-datetime` before recording.

## Security Modes (BLE only)

| Mode | Bonding window | Notes |
|------|---------------|-------|
| `mode2` **(default)** | 2 minutes after battery insertion | Bluetooth icon flashes during window |
| `mode1` | Any time during a connection | No battery pull needed to pair |

```
python3 nonin_cli.py config ADDR get-security
python3 nonin_cli.py config ADDR set-security mode1
```

The device stores up to 7 bonds. The 8th replaces the least recently used.

## Notes

- BLE: first connection auto-pairs on Linux. Other platforms show an OS pairing prompt.
- BLE: security mode 2 (default) requires batteries inserted within the last 2 minutes to pair.
- Classic: pair via `bluetoothctl pair ADDR` with the PIN from the device label.
- Classic: some commands (security, bond management, turn-off-upon-disconnect) are BLE-only.
- Run `nonin_cli.py config --help` for detailed descriptions of every setting.
