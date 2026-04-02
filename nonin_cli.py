#!/usr/bin/env python3
import argparse
import asyncio
import json
import socket
import struct
import sys
from datetime import datetime

import nonin_lib.common as nonin_lib
import nonin_lib.ble as nonin_ble
import nonin_lib.ssp as nonin_serial


# Output sinks and formatters

def _flatten(data: dict, prefix: str = "") -> dict:
    out = {}
    for k, v in data.items():
        key = f"{prefix}{k}" if not prefix else f"{prefix}_{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key))
        elif isinstance(v, list):
            out[key] = json.dumps(v)
        else:
            out[key] = v
    return out


def _extract_spo2_pr(stream: str, data: dict) -> tuple:
    if "spo2" in data or "pulse_rate" in data:
        return data.get("spo2"), data.get("pulse_rate")
    # Raw DF2/DF7 field names
    if stream in ("df2", "df7"):
        return data.get("spo2_display"), data.get("pr_display")
    return None, None


UDP_OXI_MAGIC = b"\x55\xAB"
UDP_OXI_INVALID = 0x07FF

PREDEFINED_FORMATS = {"kv", "csv", "airbridge"}


class OutputSink:
    """Manages output destination (stdout, file, or UDP) and formatting."""

    def __init__(self, output_spec: str = None, fmt: str = "kv"):
        self._fmt = fmt
        self._udp_sock = None
        self._udp_dest = None
        self._file = None
        self._close_file = False
        self._csv_header_printed = {}

        if output_spec and output_spec.startswith("udp:"):
            rest = output_spec[4:]
            host, _, port = rest.rpartition(":")
            if not host:
                host = "127.0.0.1"
            # Resolve hostname once at init
            infos = socket.getaddrinfo(host, int(port), type=socket.SOCK_DGRAM)
            if not infos:
                raise RuntimeError(f"Cannot resolve {host}")
            af, socktype, proto, _, addr = infos[0]
            self._udp_dest = addr
            self._udp_sock = socket.socket(af, socktype, proto)
        elif output_spec:
            self._file = open(output_spec, "wb" if fmt == "airbridge" else "w")
            self._close_file = True
        else:
            self._file = sys.stdout

    def write(self, stream: str, data: dict):
        if self._fmt == "airbridge":
            spo2, pr = _extract_spo2_pr(stream, data)
            if spo2 is None:
                spo2 = UDP_OXI_INVALID
            if pr is None:
                pr = UDP_OXI_INVALID
            packet = UDP_OXI_MAGIC + b"\x00" + struct.pack("<HH", spo2, pr)
            if self._udp_sock:
                self._udp_sock.sendto(packet, self._udp_dest)
            elif self._file:
                if hasattr(self._file, "buffer"):
                    self._file.buffer.write(packet)
                    self._file.buffer.flush()
                else:
                    self._file.write(packet)
                    self._file.flush()
            return

        # Text formats
        if self._fmt == "csv":
            if stream not in self._csv_header_printed:
                header = ",".join(["ts", "stream"] + list(_flatten(data).keys()))
                self._send_text(header)
                self._csv_header_printed[stream] = True
            ts = datetime.now().isoformat(timespec="milliseconds")
            values = [ts, stream] + [str(v) for v in _flatten(data).values()]
            line = ",".join(values)
        elif self._fmt == "kv":
            ts = datetime.now().isoformat(timespec="milliseconds")
            parts = [f"ts={ts}", f"stream={stream}"]
            for k, v in _flatten(data).items():
                parts.append(f"{k}={v}")
            line = " ".join(parts)
        else:
            # custom python format string
            flat = _flatten(data)
            flat["ts"] = datetime.now().isoformat(timespec="milliseconds")
            flat["stream"] = stream
            line = self._fmt.format(**flat)

        self._send_text(line)

    def _send_text(self, line: str):
        if self._udp_sock:
            self._udp_sock.sendto(line.encode() + b"\n", self._udp_dest)
        elif self._file:
            self._file.write(line + "\n")
            self._file.flush()

    def close(self):
        if self._udp_sock:
            self._udp_sock.close()
        if self._close_file and self._file:
            self._file.close()


# Stream transforms

class PassthroughTransform:

    def __init__(self, callback):
        self._callback = callback

    def __call__(self, stream: str, data: dict):
        self._callback(stream, data)


class CollectTransform:
    """Accumulates fields across DF2/DF7 frames, emits merged records.

    DF2/DF7 spread SpO2, PR, and status across a 25-frame cycle.
    This transform collects specified fields and emits one record
    per cycle with stable field names.

    fields: list of field names to collect. Each maps to specific
            frame IDs in the DF2/DF7 cycle. Default: spo2, pulse_rate.
    """

    # Map from output field name to (frame_id, source_key) pairs (1-based)
    DF2_FIELD_MAP = {
        "spo2": [(3, "spo2")],
        "pulse_rate": [(1, "hr_msb"), (2, "hr_lsb")],
        "spo2_display": [(9, "spo2_display")],
        "spo2_fast": [(10, "spo2_fast")],
        "spo2_b2b": [(11, "spo2_b2b")],
        "e_spo2": [(16, "e_spo2")],
        "pulse_rate_ext": [(14, "e_hr_msb"), (15, "e_hr_lsb")],
        "pulse_rate_display": [(20, "hr_d_msb"), (21, "hr_d_lsb")],
        "low_battery": [(8, "low_battery")],
        "smartpoint": [(8, "smartpoint")],
    }

    def __init__(self, callback, fields=None):
        self._callback = callback
        self._fields = fields or ["spo2", "pulse_rate"]
        self._acc = {}
        self._last_frame_id = -1

    def __call__(self, stream: str, data: dict):
        frame_id = data.get("frame_id")
        if frame_id is None:
            # Non-DF2 data (oximetry, df8, df13) - pass through
            self._callback(stream, data)
            return

        # Detect cycle boundary (sync bit resets frame_id to 1)
        if frame_id == 1 and self._last_frame_id > 1 and self._acc:
            self._emit(stream, data)

        self._last_frame_id = frame_id

        # Accumulate fields from this frame
        for field in self._fields:
            mappings = self.DF2_FIELD_MAP.get(field, [])
            for fid, src_key in mappings:
                if frame_id == fid and src_key in data:
                    self._acc[src_key] = data[src_key]

        # Always track pleth for waveform
        if "pleth" in data:
            self._acc["pleth"] = data["pleth"]

    def _emit(self, stream: str, data: dict):
        record = {}

        for field in self._fields:
            mappings = self.DF2_FIELD_MAP.get(field, [])
            if len(mappings) == 2 and mappings[0][1].endswith("_msb"):
                # Reconstruct 9-bit HR from MSB + LSB
                # HR format: MSB byte has HR8 in bit 0, LSB byte has HR6..HR0
                msb_key = mappings[0][1]
                lsb_key = mappings[1][1]
                msb = self._acc.get(msb_key)
                lsb = self._acc.get(lsb_key)
                if lsb is not None:
                    hr = ((msb & 0x01) << 7 | (lsb & 0x7F)) if msb is not None else (lsb & 0x7F)
                    record[field] = None if hr == 511 else hr
            else:
                # Single-value fields
                src_key = mappings[0][1] if mappings else field
                val = self._acc.get(src_key)
                if val is not None:
                    record[field] = val

        self._acc.clear()

        if record:
            self._callback(stream, record)


class ThrottleTransform:
    """Rate-limits output to N emissions per second."""

    def __init__(self, callback, hz: float):
        self._callback = callback
        self._interval = 1.0 / hz
        self._last_emit = 0

    def __call__(self, stream: str, data: dict):
        import time
        now = time.monotonic()
        if now - self._last_emit >= self._interval:
            self._callback(stream, data)
            self._last_emit = now


def parse_transform(spec: str, callback):
    """Parse a --transform spec string into a transform instance.

    Formats:
        passthrough              - no-op (default)
        collect                  - collect spo2,pulse_rate from DF2 frames
        collect:spo2,pulse_rate,low_battery  - collect specified fields
        throttle:N               - limit to N Hz
        collect|throttle:3       - chain: collect then throttle to 3Hz
    """
    if not spec or spec == "passthrough":
        return PassthroughTransform(callback)

    # Parse chain (pipe-separated)
    parts = spec.split("|")
    # Build chain right-to-left: last transform wraps callback,
    # each preceding one wraps the next
    chain = callback
    for part in reversed(parts):
        part = part.strip()
        if part == "passthrough":
            chain = PassthroughTransform(chain)
        elif part.startswith("collect"):
            if ":" in part:
                fields = part.split(":", 1)[1].split(",")
            else:
                fields = None
            chain = CollectTransform(chain, fields=fields)
        elif part.startswith("throttle:"):
            hz = float(part.split(":", 1)[1])
            chain = ThrottleTransform(chain, hz)
        else:
            raise ValueError(f"Unknown transform: {part}")

    return chain


# CLI commands

async def cmd_scan(args):
    if args.serial:
        ports = nonin_serial.scan_serial()
        if not ports:
            print("No serial ports found.")
        else:
            for p in ports:
                print(f"  {p['port']}  ({p['description']})")
        return

    seen = set()

    def on_found(address, name):
        if address not in seen:
            seen.add(address)
            print(f"  {address}  {name}")

    print("Scanning for Nonin BLE devices... (Ctrl+C to stop)")
    await nonin_ble.scan_continuous(on_found)
    print(f"\n{len(seen)} device(s) found.")


async def cmd_stream(args):
    sink = OutputSink(args.output, args.format)
    transform = parse_transform(args.transform, sink.write)

    def on_data(stream: str, data: dict):
        transform(stream, data)

    try:
        if args.serial:
            client = nonin_serial.NoninSerial(port=args.port, address=args.address)
            client.connect()
            print(f"Connected. Streaming {args.df}... (Ctrl+C to stop)", file=sys.stderr)
            df = nonin_lib.resolve_data_format(args.df)
            try:
                client.stream(df, on_data)
            except KeyboardInterrupt:
                pass
            finally:
                client.disconnect()
        else:
            streams = [s.strip() for s in args.streams.split(",")]
            client = nonin_ble.NoninBLE(args.address)
            print(f"Connecting to {args.address}...", file=sys.stderr)
            await client.connect()
            print("Connected. Streaming... (Ctrl+C to stop)", file=sys.stderr)
            await client.subscribe(streams, on_data)
            try:
                while client.is_connected:
                    await asyncio.sleep(1)
            except KeyboardInterrupt:
                pass
            finally:
                await client.disconnect()
    finally:
        sink.close()


async def cmd_download(args):
    output = sys.stdout
    close_output = False

    if args.output:
        output = open(args.output, "w")
        close_output = True

    after = datetime.fromisoformat(args.after) if args.after else None
    before = datetime.fromisoformat(args.before) if args.before else None
    max_sessions = args.first if args.first else None
    skip_sessions = args.skip if args.skip else 0

    def on_progress(byte_count):
        print(f"\r  Received {byte_count} bytes...", end="", file=sys.stderr)

    try:
        if args.serial:
            client = nonin_serial.NoninSerial(port=args.port, address=args.address)
            client.connect()
            print("Downloading stored records...", file=sys.stderr)
            sessions = client.download_memory(
                after=after, before=before,
                max_sessions=max_sessions, skip_sessions=skip_sessions,
                progress_callback=on_progress)
            print(f"\n  {len(sessions)} session(s) downloaded.", file=sys.stderr)
            client.disconnect()
        else:
            client = nonin_ble.NoninBLE(args.address)
            print(f"Connecting to {args.address}...", file=sys.stderr)
            await client.connect()
            print("Downloading stored records...", file=sys.stderr)
            sessions = await client.download_memory(
                after=after, before=before,
                max_sessions=max_sessions, skip_sessions=skip_sessions,
                progress_callback=on_progress)
            print(f"\n  {len(sessions)} session(s) downloaded.", file=sys.stderr)
            await client.disconnect()

        if not sessions:
            print("No stored sessions found.", file=sys.stderr)
            return

        if args.csv:
            output.write("session,sample,timestamp,spo2,pulse_rate\n")
            for si, session in enumerate(sessions):
                interval = session["seconds_per_sample"]
                start = session["start_time"]
                for ji, (spo2, pr) in enumerate(session["samples"]):
                    if start:
                        from datetime import timedelta
                        ts = (start + timedelta(seconds=ji * interval)).isoformat()
                    else:
                        ts = str(ji * interval)
                    spo2_s = "" if spo2 is None else str(spo2)
                    pr_s = "" if pr is None else str(pr)
                    output.write(f"{si},{ji},{ts},{spo2_s},{pr_s}\n")
        elif args.raw:
            for si, session in enumerate(sessions):
                output.write(f"session={si}\n")
                output.write(f"seconds_per_sample={session['seconds_per_sample']}\n")
                output.write(f"start_time={session['start_time'].isoformat() if session['start_time'] else ''}\n")
                output.write(f"stop_time={session['stop_time'].isoformat() if session['stop_time'] else ''}\n")
                output.write(f"samples={len(session['samples'])}\n")
                for spo2, pr in session["samples"]:
                    spo2_s = "" if spo2 is None else str(spo2)
                    pr_s = "" if pr is None else str(pr)
                    output.write(f"{spo2_s},{pr_s}\n")
                output.write("\n")
        else:
            for si, session in enumerate(sessions):
                start = session["start_time"]
                stop = session["stop_time"]
                n = len(session["samples"])
                interval = session["seconds_per_sample"]
                start_s = start.strftime("%Y-%m-%d %H:%M:%S") if start else "unknown"
                stop_s = stop.strftime("%Y-%m-%d %H:%M:%S") if stop else "unknown"

                valid = [(s, p) for s, p in session["samples"] if s is not None]
                if valid:
                    spo2_vals = [s for s, _ in valid]
                    pr_vals = [p for _, p in valid if p is not None]
                    spo2_avg = sum(spo2_vals) / len(spo2_vals)
                    pr_avg = sum(pr_vals) / len(pr_vals) if pr_vals else 0
                    spo2_min = min(spo2_vals)
                    spo2_max = max(spo2_vals)
                else:
                    spo2_avg = spo2_min = spo2_max = pr_avg = 0

                print(f"Session {si + 1}:")
                print(f"  Start:    {start_s}")
                print(f"  Stop:     {stop_s}")
                print(f"  Interval: {interval}s")
                print(f"  Samples:  {n}")
                if valid:
                    print(f"  SpO2:     avg={spo2_avg:.0f} min={spo2_min} max={spo2_max}")
                    print(f"  PR:       avg={pr_avg:.0f}")
                print()

        output.flush()
    finally:
        if close_output:
            output.close()


async def cmd_config(args):
    if args.serial:
        if args.action in BLE_ONLY_COMMANDS:
            print(f"Error: '{args.action}' is only available over BLE, not serial.", file=sys.stderr)
            return
        client = nonin_serial.NoninSerial(port=args.port, address=args.address)
        try:
            client.connect()
            result = args.config_func(client, args)
            if asyncio.iscoroutine(result):
                await result
        finally:
            client.disconnect()
    else:
        client = nonin_ble.NoninBLE(args.address)
        try:
            await client.connect()
            await args.config_func(client, args)
        finally:
            await client.disconnect()


# Config sub-handlers
# These use `await` on client methods. For BLE, methods are async coroutines.
# For serial, methods return plain values. We use _call() to handle both.

async def _call(method, *args, **kwargs):
    result = method(*args, **kwargs)
    if asyncio.iscoroutine(result):
        return await result
    return result

BLE_ONLY_COMMANDS = {
    "get-security", "set-security", "delete-bond", "turn-off-upon-disconnect",
}

async def cfg_get_datetime(client, args):
    dt = await _call(client.get_datetime)
    if args.raw:
        print(f"datetime={dt.isoformat()}")
    else:
        print(f"Device date/time: {dt.strftime('%Y-%m-%d %H:%M:%S')}")


async def cfg_set_datetime(client, args):
    if args.time:
        dt = datetime.fromisoformat(args.time)
    else:
        dt = datetime.now()
    await _call(client.set_datetime, dt)
    if args.raw:
        print(f"datetime={dt.isoformat()}")
    else:
        print(f"Device date/time set to {dt.strftime('%Y-%m-%d %H:%M:%S')}")


async def cfg_get_activation(client, args):
    mode, name = await _call(client.get_activation_mode)
    if args.raw:
        print(f"activation=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.ACTIVATION_MODE_DESC.get(mode, name)
        print(f"Activation mode: {desc}")


async def cfg_set_activation(client, args):
    mode = nonin_lib.resolve_activation_mode(args.mode)
    await _call(client.set_activation_mode, mode)
    name = nonin_lib.ACTIVATION_MODES.get(mode, "?")
    if args.raw:
        print(f"activation=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.ACTIVATION_MODE_DESC.get(mode, name)
        print(f"Activation mode set: {desc}")


async def cfg_get_display(client, args):
    mode, name = await _call(client.get_display_mode)
    if args.raw:
        print(f"display=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.DISPLAY_MODE_DESC.get(mode, name)
        print(f"Display mode: {desc}")


async def cfg_set_display(client, args):
    mode = nonin_lib.resolve_display_mode(args.mode)
    await _call(client.set_display_mode, mode)
    name = nonin_lib.DISPLAY_MODES.get(mode, "?")
    if args.raw:
        print(f"display=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.DISPLAY_MODE_DESC.get(mode, name)
        print(f"Display mode set: {desc}")


async def cfg_get_storage_rate(client, args):
    rate, name = await _call(client.get_storage_rate)
    if args.raw:
        print(f"storage_rate=0x{rate:02X} name={name}")
    else:
        desc = nonin_lib.STORAGE_RATE_DESC.get(rate, name)
        print(f"Storage rate: {desc}")


async def cfg_set_storage_rate(client, args):
    rate = nonin_lib.resolve_storage_rate(args.rate)
    await _call(client.set_storage_rate, rate)
    name = nonin_lib.STORAGE_RATES.get(rate, "?")
    if args.raw:
        print(f"storage_rate=0x{rate:02X} name={name}")
    else:
        desc = nonin_lib.STORAGE_RATE_DESC.get(rate, name)
        print(f"Storage rate set: {desc}")


async def cfg_get_device_id(client, args):
    text = await _call(client.get_device_id)
    if args.raw:
        print(f"device_id={text}")
    elif text:
        print(f"Device ID: {text}")
    else:
        print("Device ID: (not set)")


async def cfg_set_device_id(client, args):
    await _call(client.set_device_id, args.text)
    if args.raw:
        print(f"device_id={args.text}")
    else:
        print(f"Device ID set to: {args.text}")


async def cfg_get_security(client, args):
    mode, name = await _call(client.get_security_mode)
    if args.raw:
        print(f"security=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.SECURITY_MODE_DESC.get(mode, name)
        print(f"Security: {desc}")


async def cfg_set_security(client, args):
    mode = nonin_lib.resolve_security_mode(args.mode)
    await _call(client.set_security_mode, mode)
    name = nonin_lib.SECURITY_MODES.get(mode, "?")
    if args.raw:
        print(f"security=0x{mode:02X} name={name}")
    else:
        desc = nonin_lib.SECURITY_MODE_DESC.get(mode, name)
        print(f"Security set: {desc}")


async def cfg_get_config(client, args):
    cfg = await _call(client.get_config)
    if args.raw:
        for k, v in cfg.items():
            if k.startswith("_"):
                continue
            print(f"{k}={v}")
        return

    print("Device Configuration:")
    print(f"  Activation mode:  {cfg['activation_mode']}")
    print(f"  Storage rate:     {cfg['storage_rate']}")
    print(f"  Display mode:     {cfg['display_mode']}")
    if cfg.get("device_id"):
        print(f"  Device ID:        {cfg['device_id']}")
    else:
        print("  Device ID:        (not set)")

    print(f"  Software rev:     {cfg['software_revision']}")
    print(f"  Software date:    {cfg['software_revision_date']}")

    windows = []
    for i in range(1, 4):
        start = cfg[f"start_time_{i}"]
        stop = cfg[f"stop_time_{i}"]
        windows.append((i, start, stop))

    has_windows = any(s != t for _, s, t in windows)
    if has_windows:
        print("  Time windows:")
        for i, start, stop in windows:
            print(f"    Window {i}: {start} -> {stop}")
    else:
        print("  Time windows:     (none configured)")

    print(f"  Checksum valid:   {'yes' if cfg['checksum_valid'] else 'NO'}")


async def cfg_set_config(client, args):
    await _call(client.set_config,
        activation_option=nonin_lib.resolve_activation_mode(args.activation),
        storage_rate=nonin_lib.resolve_storage_rate(args.storage_rate),
        display_option=nonin_lib.resolve_display_mode(args.display),
        start_time_1=args.start1,
        stop_time_1=args.stop1,
        start_time_2=args.start2,
        stop_time_2=args.stop2,
        start_time_3=args.start3,
        stop_time_3=args.stop3,
        device_id=args.device_id,
    )
    print("Configuration written.")


async def cfg_delete_bond(client, args):
    op = nonin_lib.resolve_delete_bond_op(args.operation)
    name = nonin_lib.DELETE_BOND_OPS.get(op, f"0x{op:02X}")
    await _call(client.delete_bond, op)
    print(f"Bond(s) deleted ({name}).")


async def cfg_clear_memory(client, args):
    await _call(client.clear_memory)
    print("Device memory cleared.")


async def cfg_turn_off_upon_disconnect(client, args):
    await _call(client.turn_off_upon_disconnect)
    print("Turn-off-upon-disconnect enabled.")
    print("  (only effective in Bluetooth Connection activation mode)")


# Argument parser

EPILOG_STREAM = """\
output formats (--format):
  kv          key=value pairs (default): ts=... spo2=98 pulse_rate=72 ...
  csv         CSV with auto-printed header row
  airbridge   7-byte binary UDP oximetry protocol (for use with -o udp:...)
  '{...}'     custom Python format string, e.g. '{spo2},{pulse_rate}'

output sinks (-o):
  (default)         stdout
  path/to/file      write to file
  udp:host:port     send to UDP endpoint, e.g. -o udp:127.0.0.1:8025

transforms (--transform / -t):
  passthrough              every packet as-is (default)
  collect                  merge DF2 25-frame cycle into one record (3Hz)
                           default fields: spo2, pulse_rate
  collect:spo2,pulse_rate,low_battery   collect specific fields
  throttle:N               drop packets to limit output to N Hz
  collect|throttle:3       chain: collect then throttle

  collect fields: spo2, pulse_rate, spo2_display, spo2_fast, spo2_b2b,
                  e_spo2, pulse_rate_ext, pulse_rate_display,
                  low_battery, smartpoint

examples:
  stream ADDR                                      # kv to stdout
  stream ADDR -f csv -o data.csv                   # csv to file
  stream ADDR -f airbridge -o udp:127.0.0.1:8025   # airbridge to UDP
  stream ADDR -f csv -o udp:10.0.0.1:9000          # csv lines over UDP
  --serial stream ADDR --df df2 -t collect -f airbridge -o udp:...:8025
  --serial stream ADDR --df df2 -t 'collect:spo2,pulse_rate,smartpoint'

BLE streams (--streams):
  oximetry    SpO2, pulse rate, PAI, battery (1/s)
  df20        Pulse interval timing, up to 6 pulses/packet
  df22        Raw PPG waveform, 25 samples/packet (75 Hz)
  df23        Device status: sensor type, errors, battery %
  all         Subscribe to all streams

format string fields (oximetry):
  {spo2} {pulse_rate} {pai} {battery_voltage} {counter}
  {flags_encrypted} {flags_low_battery} {flags_sensor_attached}
  {flags_searching} {flags_smartpoint} {flags_weak_signal}
"""

EPILOG_CONFIG = """\
activation modes:
  sensor       Device turns on when sensor is connected. Turns off when sensor
               disconnects or after 10 minutes of invalid readings.
  programmed   Device turns on/off per configured time windows (requires sensor).
               Use set-config to define up to 3 start/stop time pairs.
  spot-check   Device turns on when a finger is inserted into the sensor.
               Turns off when finger is removed for 10s, sensor disconnects,
               or after 3 minutes of invalid readings.
  bluetooth    Device turns on when a BLE collector connects. Turns off when
               BLE disconnects (if no sensor or 10min invalid readings).
               Supports turn-off-upon-disconnect command for immediate shutdown.

display modes:
  full         SpO2, pulse rate, pulse bar graph, and battery all shown.
  partial      SpO2 and pulse rate hidden from the LCD display.
  mvi          Display always on. Shows stored data volume (hours:minutes)
               instead of SpO2/pulse rate. (Memory Volume Indicator)

storage rates:
  1s           1 sample/second,  max ~274 hours storage
  2s           1 sample/2 seconds, max ~548 hours storage
  4s           1 sample/4 seconds, max ~1097 hours storage (default)

security modes:
  mode1        Allows new BLE bonds during any connection.
  mode2        Allows new bonds only within 2 minutes of battery insertion.
               This is the default. The Bluetooth icon flashes during the
               bonding window. Window closes on first bond or connection.

bond operations:
  all                  Delete all stored bonds (max 7).
  current              Delete only the current collector's bond.
  all-except-current   Delete all bonds except the current collector's.

all values also accept hex (e.g. 0x31)
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nonin_cli",
        description="Nonin WristOx2 3150 BLE/Classic command-line tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--serial", action="store_true",
                        help="Use serial/SPP transport instead of BLE")
    parser.add_argument("--port", default=None,
                        help="Serial port path (e.g. /dev/rfcomm0). "
                             "If not given, auto-binds rfcomm from the device address.")
    sub = parser.add_subparsers(dest="command", required=True)

    # scan
    sub.add_parser("scan",
                    help="Scan for devices (BLE by default, serial ports with --serial)")

    # stream
    p_stream = sub.add_parser("stream",
                              help="Stream live sensor readings",
                              epilog=EPILOG_STREAM,
                              formatter_class=argparse.RawDescriptionHelpFormatter)
    p_stream.add_argument("address", help="Device MAC address")
    p_stream.add_argument("--streams", default="oximetry",
                          help="BLE: comma-separated list (default: oximetry)")
    p_stream.add_argument("--df", default="df8",
                          help="Serial: data format - df2 (75Hz), df7 (75Hz 16-bit), "
                               "df8 (1Hz), df13 (spot-check). Default: df8")
    p_stream.add_argument("--format", "-f", dest="format", default="kv",
                          help="Output format: kv (default), csv, airbridge, "
                               "or a Python format string (e.g. '{spo2},{pulse_rate}')")
    p_stream.add_argument("-o", "--output", default=None,
                          help="Output sink: file path, or udp:host:port. "
                               "Default: stdout")
    p_stream.add_argument("--transform", "-t", default="passthrough",
                          help="Data transform pipeline. "
                               "passthrough (default), "
                               "collect[:field1,field2,...], "
                               "throttle:N (Hz). "
                               "Chain with |, e.g. 'collect|throttle:3'")

    # download
    p_dl = sub.add_parser("download",
                           help="Download stored sessions from device memory",
                           formatter_class=argparse.RawDescriptionHelpFormatter,
                           epilog="""\
output formats:
  default     Session summary with averages and min/max
  --csv       CSV: session,sample,timestamp,spo2,pulse_rate
  --raw       Key=value headers + raw spo2,pr per line

Sessions are returned newest first. Timestamps are based on the
device clock (set with: config <addr> set-datetime).
""")
    p_dl.add_argument("address", help="Device MAC address")
    p_dl.add_argument("--after", default=None,
                       help="Only sessions starting at or after this time (ISO format). "
                            "Cancels download early once older sessions are reached.")
    p_dl.add_argument("--before", default=None,
                       help="Only sessions starting before this time (ISO format)")
    p_dl.add_argument("--first", type=int, default=None,
                       help="Download only the N most recent sessions, then cancel")
    p_dl.add_argument("--skip", type=int, default=0,
                       help="Skip the first N sessions (newest)")
    p_dl.add_argument("--csv", action="store_true", help="Output as CSV")
    p_dl.add_argument("--raw", action="store_true", help="Raw key=value output")
    p_dl.add_argument("-o", "--output", default=None, help="Write to file instead of stdout")

    # config
    p_cfg = sub.add_parser("config",
                           help="Read/write device configuration",
                           epilog=EPILOG_CONFIG,
                           formatter_class=argparse.RawDescriptionHelpFormatter)
    p_cfg.add_argument("address", help="Device MAC address")
    p_cfg.add_argument("--raw", action="store_true",
                       help="Output raw key=value pairs for scripting")
    cfg_sub = p_cfg.add_subparsers(dest="action", required=True)

    p = cfg_sub.add_parser("get-datetime", help="Read device clock")
    p.set_defaults(config_func=cfg_get_datetime)

    p = cfg_sub.add_parser("set-datetime", help="Set device clock (default: now)")
    p.add_argument("--time", default=None,
                   help="ISO format, e.g. '2026-03-30 14:30:00' (default: current time)")
    p.set_defaults(config_func=cfg_set_datetime)

    p = cfg_sub.add_parser("get-activation", help="Read activation mode")
    p.set_defaults(config_func=cfg_get_activation)

    p = cfg_sub.add_parser("set-activation",
                           help="Set activation mode (sensor|programmed|spot-check|bluetooth)")
    p.add_argument("mode",
                   help="sensor: on at sensor connect | programmed: per time windows | "
                        "spot-check: on at finger insert | bluetooth: on at BLE connect")
    p.set_defaults(config_func=cfg_set_activation)

    p = cfg_sub.add_parser("get-display", help="Read display mode")
    p.set_defaults(config_func=cfg_get_display)

    p = cfg_sub.add_parser("set-display", help="Set display mode (full|partial|mvi)")
    p.add_argument("mode",
                   help="full: all readings shown | partial: readings hidden | "
                        "mvi: always-on, shows memory usage")
    p.set_defaults(config_func=cfg_set_display)

    p = cfg_sub.add_parser("get-storage-rate", help="Read storage rate")
    p.set_defaults(config_func=cfg_get_storage_rate)

    p = cfg_sub.add_parser("set-storage-rate", help="Set storage rate (1s|2s|4s)")
    p.add_argument("rate",
                   help="1s: ~274h capacity | 2s: ~548h | 4s: ~1097h (default)")
    p.set_defaults(config_func=cfg_set_storage_rate)

    p = cfg_sub.add_parser("get-device-id", help="Read device identification string")
    p.set_defaults(config_func=cfg_get_device_id)

    p = cfg_sub.add_parser("set-device-id", help="Set device identification string")
    p.add_argument("text", help="ASCII string, max 50 characters")
    p.set_defaults(config_func=cfg_set_device_id)

    p = cfg_sub.add_parser("get-security", help="Read security mode")
    p.set_defaults(config_func=cfg_get_security)

    p = cfg_sub.add_parser("set-security", help="Set security mode (mode1|mode2)")
    p.add_argument("mode",
                   help="mode1: bonds anytime | mode2: bonds only within 2min of battery insert (default)")
    p.set_defaults(config_func=cfg_set_security)

    p = cfg_sub.add_parser("get-config", help="Read full device configuration")
    p.set_defaults(config_func=cfg_get_config)

    p = cfg_sub.add_parser("set-config", help="Write full configuration block")
    p.add_argument("--activation", required=True, help="sensor|programmed|spot-check|bluetooth")
    p.add_argument("--storage-rate", required=True, help="1s|2s|4s")
    p.add_argument("--display", required=True, help="full|partial|mvi")
    p.add_argument("--start1", required=True, help="Start time 1 (YYMMDDhhmm)")
    p.add_argument("--stop1", required=True, help="Stop time 1 (YYMMDDhhmm)")
    p.add_argument("--start2", required=True, help="Start time 2 (YYMMDDhhmm)")
    p.add_argument("--stop2", required=True, help="Stop time 2 (YYMMDDhhmm)")
    p.add_argument("--start3", required=True, help="Start time 3 (YYMMDDhhmm)")
    p.add_argument("--stop3", required=True, help="Stop time 3 (YYMMDDhhmm)")
    p.add_argument("--device-id", required=True, help="Device ID (max 50 ASCII chars)")
    p.set_defaults(config_func=cfg_set_config)

    p = cfg_sub.add_parser("delete-bond", help="Delete BLE bond(s)")
    p.add_argument("operation",
                   help="all: delete all bonds | current: only this collector | "
                        "all-except-current: keep only this collector")
    p.set_defaults(config_func=cfg_delete_bond)

    p = cfg_sub.add_parser("clear-memory", help="Erase all stored patient data")
    p.set_defaults(config_func=cfg_clear_memory)

    p = cfg_sub.add_parser("turn-off-upon-disconnect",
                           help="Turn off device when BLE disconnects (Bluetooth activation mode only)")
    p.set_defaults(config_func=cfg_turn_off_upon_disconnect)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "scan":
            asyncio.run(cmd_scan(args))
        elif args.command == "stream":
            asyncio.run(cmd_stream(args))
        elif args.command == "download":
            asyncio.run(cmd_download(args))
        elif args.command == "config":
            asyncio.run(cmd_config(args))
    except KeyboardInterrupt:
        pass
    except (OSError, RuntimeError, TimeoutError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
