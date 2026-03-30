# Nonin WristOx2 3150 BLE Tool

Command-line tool for configuring and reading data from Nonin WristOx2 3150 pulse oximeters over Bluetooth LE.

## Requirements

- Python 3.10+
- Bluetooth LE adapter
- [bleak](https://github.com/hbldh/bleak) BLE library

Tested on Linux. Should work on Windows and macOS via bleak's cross-platform support, but auto-pairing currently only implemented for Linux (other platforms rely on OS-level pairing dialogs).

## Quick Start

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

4. Stream live readings:
   ```
   python3 nonin_cli.py stream 08:6B:D7:13:01:E8
   ```

## Examples

### Stream SpO2 to a CSV file
```
python3 nonin_cli.py stream 08:6B:D7:13:01:E8 --csv -o readings.csv
```

### Stream all sensors at once
```
python3 nonin_cli.py stream 08:6B:D7:13:01:E8 --streams all
```

### Custom output format
```
python3 nonin_cli.py stream 08:6B:D7:13:01:E8 --format '{ts} SpO2={spo2} HR={pulse_rate}'
```

### Set the device clock to now
```
python3 nonin_cli.py config 08:6B:D7:13:01:E8 set-datetime
```

### Change activation mode
```
python3 nonin_cli.py config 08:6B:D7:13:01:E8 set-activation bluetooth
```

### Change storage rate
```
python3 nonin_cli.py config 08:6B:D7:13:01:E8 set-storage-rate 1s
```

### Scripting-friendly output
```
python3 nonin_cli.py config 08:6B:D7:13:01:E8 --raw get-activation
# activation=0x34 name=bluetooth
```

### See all available options and what they mean
```
python3 nonin_cli.py config --help
```

## Available Streams

| Stream | Data | Rate |
|--------|------|------|
| `oximetry` | SpO2, pulse rate, PAI, battery | 1/s |
| `df20` | Pulse interval timing | per pulse |
| `df22` | Raw PPG waveform (25 samples) | 3/s |
| `df23` | Device status, errors, battery % | 1/s |
| `all` | All of the above | |

## Security Modes

The device has two security modes that control when new BLE bonds are accepted:

| Mode | Bonding window | Notes |
|------|---------------|-------|
| `mode2` **(default)** | 2 minutes after battery insertion | Bluetooth icon flashes during window |
| `mode1` | Any time during a connection | No battery pull needed to pair |

```
python3 nonin_cli.py config 08:6B:D7:13:01:E8 get-security
python3 nonin_cli.py config 08:6B:D7:13:01:E8 set-security mode1
```

The device stores up to 7 bonds. The 8th replaces the least recently used.

## Notes

- The device must be paired before use. On first connection (Linux) the tool pairs automatically. On other platforms, accept the OS pairing prompt.
- In security mode 2 (default), pairing requires batteries inserted within the last 2 minutes.
- Run `nonin_cli.py config --help` for detailed descriptions of every setting.
