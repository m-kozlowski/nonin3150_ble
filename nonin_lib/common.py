from datetime import datetime
from typing import Optional


# BLE UUIDs

NONIN_SERVICE_UUID = "46A970E0-0D5F-11E2-8B5E-0002A5D5C51B"
CONTINUOUS_OXIM_UUID = "0AAD7EA0-0D60-11E2-8E3C-0002A5D5C51B"
CONTROL_POINT_UUID = "1447AF80-0D60-11E2-88B6-0002A5D5C51B"
DEVICE_STATUS_DF23_UUID = "EC0A9302-4D24-11E7-B114-B2F933D5FE66"
PULSE_INTERVAL_DF20_UUID = "34E27863-76FF-4F8E-96F1-9E3993AA6199"
PPG_DF22_UUID = "EC0A883A-4D24-11E7-B114-B2F933D5FE66"
MEMORY_PLAYBACK_UUID = "EC0A8DDA-4D24-11E7-B114-B2F933D5FE66"


# Lookup tables

STORAGE_RATES = {
    0x31: "1s",
    0x32: "2s",
    0x34: "4s",
}

STORAGE_RATE_DESC = {
    0x31: "1 second/sample  (max ~274 hours storage)",
    0x32: "2 seconds/sample (max ~548 hours storage)",
    0x34: "4 seconds/sample (max ~1097 hours storage)",
}

STORAGE_RATE_NAMES = {v: k for k, v in STORAGE_RATES.items()}

DF22_EXPECTED_LENGTH = 53

DF23_SENSOR_TYPES = {
    0x01: "Pulse Oximeter Sensor",
}

DF23_ERRORS = {
    0x00: "No error",
    0x01: "No sensor",
    0x05: "Sensor fault",
    0x06: "System error",
}

ACTIVATION_MODES = {
    0x31: "sensor",
    0x32: "programmed",
    0x33: "spot-check",
    0x34: "bluetooth",
}

ACTIVATION_MODE_DESC = {
    0x31: "Sensor        - turns on when sensor connected, off when disconnected or 10min invalid",
    0x32: "Programmed    - turns on/off per configured time windows while sensor connected",
    0x33: "Spot-Check    - turns on at finger insertion, off at removal (10s) or 3min invalid",
    0x34: "Bluetooth     - turns on at BLE connection, off at disconnect (if no sensor/10min invalid)",
}

ACTIVATION_MODE_NAMES = {v: k for k, v in ACTIVATION_MODES.items()}

SECURITY_MODES = {
    0x01: "mode1",
    0x02: "mode2",
}

SECURITY_MODE_DESC = {
    0x01: "Mode 1 - allows new bonds during each connection (no battery pull needed)",
    0x02: "Mode 2 - allows new bonds only within 2 min of battery insertion (default)",
}

SECURITY_MODE_NAMES = {v: k for k, v in SECURITY_MODES.items()}

DISPLAY_MODES = {
    0x31: "full",
    0x32: "partial",
    0x33: "mvi",
}

DISPLAY_MODE_DESC = {
    0x31: "Full    - SpO2, PR, pulse bar, battery status all shown",
    0x32: "Partial - SpO2 and PR hidden from display",
    0x33: "MVI     - display always on, shows memory usage instead of readings",
}

DISPLAY_MODE_NAMES = {v: k for k, v in DISPLAY_MODES.items()}

DELETE_BOND_OPS = {
    0x00: "all",
    0x01: "current",
    0x02: "all-except-current",
}

DELETE_BOND_OP_NAMES = {v: k for k, v in DELETE_BOND_OPS.items()}


# Parsers

def parse_continuous_oximetry(data: bytearray) -> dict:
    status = data[1]
    batt_voltage = data[2] * 0.1
    pai = ((data[3] << 8) | data[4]) / 100.0
    counter = (data[5] << 8) | data[6]
    spo2 = None if data[7] == 127 else data[7]
    pr_raw = (data[8] << 8) | data[9]
    pulse_rate = None if pr_raw == 511 else pr_raw

    flags = {
        "encrypted": bool(status & (1 << 6)),
        "low_battery": bool(status & (1 << 5)),
        "sensor_attached": bool(status & (1 << 4)),
        "searching": bool(status & (1 << 3)),
        "smartpoint": bool(status & (1 << 2)),
        "weak_signal": bool(status & (1 << 1)),
    }

    return {
        "battery_voltage": batt_voltage,
        "pai": pai,
        "counter": counter,
        "spo2": spo2,
        "pulse_rate": pulse_rate,
        "flags": flags,
    }


def parse_df20_pulse_field(raw: bytes) -> dict:
    if len(raw) != 4:
        raise ValueError("Pulse field must be exactly 4 bytes")
    status_mso = raw[0]
    pai_lso = raw[1]
    pulse_time = int.from_bytes(raw[2:4], "big")
    bad_pulse = bool(status_mso & 0x80)
    pai_mso = status_mso & 0x0F
    pai_raw = (pai_mso << 8) | pai_lso
    pai_pct = pai_raw / 100.0
    return {
        "bad_pulse": bad_pulse,
        "pai_raw": pai_raw,
        "pai_percent": pai_pct,
        "pulse_interval_ms": pulse_time * 0.1,
    }


def parse_df20_payload(payload: bytes) -> dict:
    if len(payload) < 4:
        raise ValueError(f"DF20 frame too short: {len(payload)} bytes")
    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(f"DF20 length mismatch: header={pkt_len}, actual={len(payload)}")
    counter = int.from_bytes(payload[1:3], "big")
    status = payload[3]
    invalid_signal = bool(status & 0x01)
    pulse_rate_too_high = bool(status & 0x02)
    pulses = []
    if not (invalid_signal or pulse_rate_too_high):
        offset = 4
        while offset + 4 <= len(payload) and len(pulses) < 6:
            pulse_raw = payload[offset:offset + 4]
            pulses.append(parse_df20_pulse_field(pulse_raw))
            offset += 4
    return {
        "packet_length": pkt_len,
        "counter": counter,
        "status_raw": status,
        "invalid_signal": invalid_signal,
        "pulse_rate_too_high": pulse_rate_too_high,
        "pulses": pulses,
        "pulse_count": len(pulses),
    }


def parse_df22_payload(payload: bytes) -> dict:
    if len(payload) != DF22_EXPECTED_LENGTH:
        raise ValueError(f"DF22 invalid length: {len(payload)} (expected {DF22_EXPECTED_LENGTH})")
    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(f"DF22 length mismatch: header={pkt_len}, actual={len(payload)}")
    ppg_samples = []
    offset = 1
    for _ in range(25):
        sample = int.from_bytes(payload[offset:offset + 2], "big", signed=False)
        ppg_samples.append(sample)
        offset += 2
    counter = int.from_bytes(payload[offset:offset + 2], "big")
    return {
        "packet_length": pkt_len,
        "ppg_samples": ppg_samples,
        "counter": counter,
    }


def parse_df23_payload(payload: bytes) -> dict:
    if len(payload) < 7:
        raise ValueError(f"DF23 frame too short: {len(payload)} bytes")
    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(f"DF23 length mismatch: header={pkt_len}, actual={len(payload)}")
    sensor_type = payload[1]
    error_code = payload[2]
    batt_volt = payload[3]
    batt_pct = payload[4]
    tx_index = int.from_bytes(payload[5:7], "big")
    return {
        "packet_length": pkt_len,
        "sensor_type_raw": sensor_type,
        "sensor_type": DF23_SENSOR_TYPES.get(sensor_type, f"Unknown(0x{sensor_type:02X})"),
        "error_raw": error_code,
        "error": DF23_ERRORS.get(error_code, f"Unknown(0x{error_code:02X})"),
        "battery_voltage_raw": batt_volt,
        "battery_percentage": batt_pct,
        "tx_index": tx_index,
    }


def parse_datetime_payload(payload: bytes) -> datetime:
    year = int(payload[0:2].decode())
    month = int(payload[2:4].decode())
    day = int(payload[4:6].decode())
    hour = int(payload[6:8].decode())
    minute = int(payload[8:10].decode())
    second = int(payload[10:12].decode())
    return datetime(2000 + year, month, day, hour, minute, second)


def parse_activation_mode_payload(payload: bytes) -> tuple:
    mode = payload[0]
    return mode, ACTIVATION_MODES.get(mode, f"Unknown(0x{mode:02X})")


def parse_turn_off_upon_disconnect_payload(payload: bytes) -> bool:
    if payload[0] == 0x06:
        return True
    if payload[0] == 0x15:
        return False
    raise ValueError("Invalid TOUD ACK")


def parse_security_mode_response_byte(mode_byte: int) -> tuple:
    name = SECURITY_MODES.get(mode_byte, f"Unknown(0x{mode_byte:02X})")
    return mode_byte, name


def parse_display_mode_payload(payload: bytes) -> tuple:
    if len(payload) != 1:
        raise ValueError("Invalid Display Mode payload length")
    mode = payload[0]
    name = DISPLAY_MODES.get(mode, f"Unknown(0x{mode:02X})")
    return mode, name


def parse_device_id_payload(payload: bytes) -> str:
    if len(payload) != 50:
        raise ValueError("Invalid Device ID payload length")
    return payload.rstrip(b"\x00").decode("ascii", errors="strict")


def parse_cfg_time_ascii_10(raw: bytes) -> str:
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.hex()


def encode_cfg_time_ascii_10(timestr: str) -> bytes:
    if len(timestr) != 10 or not timestr.isdigit():
        raise ValueError("Time must be in 'YYMMDDhhmm' format")
    return timestr.encode("ascii")


def _decode_ascii_or_hex(raw: bytes) -> str:
    stripped = raw.rstrip(b"\x00")
    if not stripped:
        return ""
    try:
        return stripped.decode("ascii")
    except UnicodeDecodeError:
        return raw.hex()


def _format_cfg_time(raw_str: str) -> str:
    if len(raw_str) == 10 and raw_str.isdigit():
        return f"20{raw_str[0:2]}-{raw_str[2:4]}-{raw_str[4:6]} {raw_str[6:8]}:{raw_str[8:10]}"
    return raw_str


def parse_config_block_payload(payload: bytes) -> dict:
    if len(payload) != 136:
        raise ValueError(f"Invalid CFG payload length: {len(payload)}")
    cfg = {}
    cfg["activation_mode"] = ACTIVATION_MODES.get(payload[2], f"unknown(0x{payload[2]:02X})")
    cfg["activation_mode_raw"] = payload[2]
    cfg["storage_rate"] = STORAGE_RATES.get(payload[3], f"unknown(0x{payload[3]:02X})")
    cfg["storage_rate_raw"] = payload[3]
    cfg["display_mode"] = DISPLAY_MODES.get(payload[4], f"unknown(0x{payload[4]:02X})")
    cfg["display_mode_raw"] = payload[4]

    raw_times = {}
    raw_times["start_time_1"] = parse_cfg_time_ascii_10(payload[5:15])
    raw_times["stop_time_1"] = parse_cfg_time_ascii_10(payload[15:25])
    raw_times["start_time_2"] = parse_cfg_time_ascii_10(payload[25:35])
    raw_times["stop_time_2"] = parse_cfg_time_ascii_10(payload[35:45])
    raw_times["start_time_3"] = parse_cfg_time_ascii_10(payload[45:55])
    raw_times["stop_time_3"] = parse_cfg_time_ascii_10(payload[55:65])
    for k, v in raw_times.items():
        cfg[k] = _format_cfg_time(v)
        cfg[k + "_raw"] = v

    cfg["device_id"] = payload[65:115].rstrip(b"\x00").decode("ascii", "replace")
    cfg["software_revision"] = _decode_ascii_or_hex(payload[119:122])
    cfg["software_revision_date"] = _decode_ascii_or_hex(payload[122:128])

    cfg["checksum"] = int.from_bytes(payload[134:136], "big")
    checksum_calc = sum(payload[0:134]) & 0xFFFF
    cfg["checksum_valid"] = checksum_calc == cfg["checksum"]
    cfg["_raw"] = bytes(payload)
    return cfg


def parse_storage_rate_payload(payload: bytes) -> tuple:
    if len(payload) != 1:
        raise ValueError("Invalid Storage Rate payload length")
    rate = payload[0]
    name = STORAGE_RATES.get(rate, f"Unknown(0x{rate:02X})")
    return rate, name


# Command builders

def build_get_datetime_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x44, 0x54, 0x4D, 0x3F, 0x0D, 0x0A])


def build_set_datetime_command(dt: datetime):
    ts = dt.strftime("%y%m%d%H%M%S").encode()
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x12, 0x44, 0x54, 0x4D, 0x3D]) + ts + bytes([0x0D, 0x0A])


def build_get_activation_mode_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x41, 0x43, 0x54, 0x3F, 0x0D, 0x0A])


def build_set_activation_mode_command(mode: int):
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x07, 0x41, 0x43, 0x54, 0x3D, mode, 0x0D, 0x0A])


def build_turn_off_upon_disconnect_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x54, 0x4F, 0x46, 0x21, 0x0D, 0x0A])


def build_get_security_mode_command():
    return bytes([0x65, 0x4E, 0x4D, 0x49])


def build_set_security_mode_command(mode: int):
    if mode not in SECURITY_MODES:
        raise ValueError(f"Invalid security mode: 0x{mode:02X}")
    return bytes([0x64, 0x4E, 0x4D, 0x49, mode])


def build_set_display_mode_command(mode: int):
    if mode not in DISPLAY_MODES:
        raise ValueError(f"Invalid display mode: 0x{mode:02X}")
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x07, 0x44, 0x49, 0x53, 0x3D, mode, 0x0D, 0x0A])


def build_get_display_mode_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x44, 0x49, 0x53, 0x3F, 0x0D, 0x0A])


def build_set_device_id_command(text: str):
    raw = text.encode("ascii", errors="strict")
    if len(raw) > 50:
        raise ValueError("Device ID string must be <= 50 ASCII characters")
    padded = raw.ljust(50, b'\x00')
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x38, 0x49, 0x44, 0x53, 0x3D]) + padded + bytes([0x0D, 0x0A])


def build_get_device_id_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x49, 0x44, 0x53, 0x3F, 0x0D, 0x0A])


def build_get_config_block_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x43, 0x46, 0x47, 0x3F, 0x0D, 0x0A])


def build_set_configuration_command(
    *,
    activation_option: int,
    storage_rate: int,
    display_option: int,
    start_time_1: str,
    stop_time_1: str,
    start_time_2: str,
    stop_time_2: str,
    start_time_3: str,
    stop_time_3: str,
    device_id: str,
):
    payload = bytearray(136)
    payload[0:2] = b"\x00\x00"
    payload[2] = activation_option
    payload[3] = storage_rate
    payload[4] = display_option
    payload[5:15] = encode_cfg_time_ascii_10(start_time_1)
    payload[15:25] = encode_cfg_time_ascii_10(stop_time_1)
    payload[25:35] = encode_cfg_time_ascii_10(start_time_2)
    payload[35:45] = encode_cfg_time_ascii_10(stop_time_2)
    payload[45:55] = encode_cfg_time_ascii_10(start_time_3)
    payload[55:65] = encode_cfg_time_ascii_10(stop_time_3)
    raw_id = device_id.encode("ascii", errors="strict")
    if len(raw_id) > 50:
        raise ValueError("Device ID must be <= 50 ASCII characters")
    payload[65:115] = raw_id.ljust(50, b"\x00")
    payload[115:119] = b"\x00" * 4
    payload[119:122] = b"\x00\x00\x00"
    payload[122:128] = b"\x00" * 6
    payload[128:134] = b"\x00" * 6
    checksum = sum(payload[0:134]) & 0xFFFF
    payload[134:136] = checksum.to_bytes(2, "big")
    frame = bytes([0x60, 0x4E, 0x4D, 0x49, 0x8D, 0x43, 0x46, 0x47, 0x3D]) + payload + bytes([0x0D, 0x0A])
    if len(frame) != 147:
        raise RuntimeError(f"SET_CONFIGURATION frame size is {len(frame)}, expected 147")
    return frame


def build_delete_bond_command(operation: int):
    if operation not in DELETE_BOND_OPS:
        raise ValueError(f"Invalid delete bond operation: 0x{operation:02X}")
    return bytes([0x63, 0x4E, 0x4D, 0x49, operation])


def build_clear_memory_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x4D, 0x43, 0x4C, 0x21, 0x0D, 0x0A])


def build_set_storage_rate_command(rate: int):
    if rate not in STORAGE_RATES:
        raise ValueError(f"Invalid storage rate: 0x{rate:02X}")
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x07, 0x44, 0x53, 0x52, 0x3D, rate, 0x0D, 0x0A])


def build_get_storage_rate_command():
    return bytes([0x60, 0x4E, 0x4D, 0x49, 0x06, 0x44, 0x53, 0x52, 0x3F, 0x0D, 0x0A])


def build_memory_playback_command():
    return bytes([0x71, 0x4E, 0x4D, 0x49])


def build_cancel_memory_playback_command():
    return bytes([0x72, 0x4E, 0x4D, 0x49])


# Memory playback data parser

SESSION_HEADER = (0xFE, 0xFD)


def _decode_memory_time(triplets: list, idx: int) -> Optional[datetime]:
    """Decode 3 triplets into a datetime. Format: [(month,day),(year,minute),(second,hour)]."""
    if idx + 3 > len(triplets):
        return None
    month, day = triplets[idx]
    year_raw, minute = triplets[idx + 1]
    second, hour = triplets[idx + 2]
    year = 2000 + year_raw
    try:
        return datetime(year, month, day, hour, minute, second)
    except ValueError:
        return None


def parse_memory_data(raw: bytes) -> list:
    """Parse raw memory playback bytes into a list of sessions.

    Each session is a dict with:
        seconds_per_sample: int
        current_time: datetime or None
        stop_time: datetime or None
        start_time: datetime or None
        samples: list of (spo2, pulse_rate) tuples
            spo2/pr = None if invalid (255)
            pr > 200 is decompressed: 200 + (raw - 200) * 2
    """
    triplets = []
    for i in range(0, len(raw) - 2, 3):
        b0, b1, cs = raw[i], raw[i + 1], raw[i + 2]
        if (b0 + b1) % 256 != cs:
            continue  # skip invalid triplets
        triplets.append((b0, b1))

    # Locate session headers: the FE FD marker followed by "current time" block.
    headers = [
        j for j in range(len(triplets) - 10)
        if triplets[j] == SESSION_HEADER
        and _decode_memory_time(triplets, j + 2) is not None
    ]

    sessions = []
    for n, start in enumerate(headers):
        boundary = headers[n + 1] if n + 1 < len(headers) else len(triplets)
        sessions.append(_parse_session(triplets, start, boundary))
    return sessions


def _parse_session(triplets: list, start: int, boundary: int) -> dict:
    """Parse one session: an 11-triplet header followed by its samples.

    The header records the start/stop time and sampling interval, so the sample
    count is exactly (stop - start) / interval + 1.
    """
    seconds_per_sample = triplets[start + 1][0]
    fmt = triplets[start + 1][1]
    current_time = _decode_memory_time(triplets, start + 2)
    stop_time = _decode_memory_time(triplets, start + 5)
    start_time = _decode_memory_time(triplets, start + 8)

    sample_start = start + 11
    count = boundary - sample_start

    # Prefer the exact count implied by the header's time span
    # fall back to the next-header boundary when the timestamps are unusable
    if (start_time and stop_time and seconds_per_sample
            and stop_time >= start_time):
        span = int(round(
            (stop_time - start_time).total_seconds() / seconds_per_sample)) + 1
        if 0 <= span <= count:
            count = span

    samples = []
    for k in range(sample_start, sample_start + count):
        pr_raw, spo2_raw = triplets[k]  # byte0=pulse_rate, byte1=spo2
        spo2 = None if spo2_raw == 255 else spo2_raw
        if pr_raw == 255:
            pr = None
        elif pr_raw > 200:
            pr = 200 + (pr_raw - 200) * 2
        else:
            pr = pr_raw
        samples.append((spo2, pr))

    return {
        "seconds_per_sample": seconds_per_sample,
        "format": fmt,
        "current_time": current_time,
        "stop_time": stop_time,
        "start_time": start_time,
        "samples": samples,
    }


# Name resolution helpers

def resolve_activation_mode(value: str) -> int:
    if value in ACTIVATION_MODE_NAMES:
        return ACTIVATION_MODE_NAMES[value]
    return int(value, 0)


def resolve_display_mode(value: str) -> int:
    if value in DISPLAY_MODE_NAMES:
        return DISPLAY_MODE_NAMES[value]
    return int(value, 0)


def resolve_storage_rate(value: str) -> int:
    if value in STORAGE_RATE_NAMES:
        return STORAGE_RATE_NAMES[value]
    return int(value, 0)


def resolve_security_mode(value: str) -> int:
    if value in SECURITY_MODE_NAMES:
        return SECURITY_MODE_NAMES[value]
    return int(value, 0)


def resolve_delete_bond_op(value: str) -> int:
    if value in DELETE_BOND_OP_NAMES:
        return DELETE_BOND_OP_NAMES[value]
    return int(value, 0)


# Classic SPP serial data format parsers

DATA_FORMATS = {
    0x02: "df2",
    0x07: "df7",
    0x08: "df8",
    0x0D: "df13",
}

DATA_FORMAT_NAMES = {v: k for k, v in DATA_FORMATS.items()}

ACK = 0x06
NAK = 0x15
STX = 0x02
ETX = 0x03


def build_set_data_format_command(data_format: int, options: int = 0x21) -> bytes:
    """Build Level 1 binary command to set data format.

    data_format: 0x02 (DF2), 0x07 (DF7), 0x08 (DF8), 0x0D (DF13)
    options: bit field - bit 0 must be 1, bit 5 = BT enabled, bit 6 = spot-check
    """
    opcode = 0x70
    data_size = 0x04
    data_type = 0x02
    checksum = (opcode + data_size + data_type + data_format + options) & 0xFF
    return bytes([STX, opcode, data_size, data_type, data_format, options, checksum, ETX])


def resolve_data_format(value: str) -> int:
    v = value.lower()
    if v in DATA_FORMAT_NAMES:
        return DATA_FORMAT_NAMES[v]
    return int(value, 0)


_df2_frame_counter = 0


def parse_df2_packet(data: bytes) -> dict:
    """Parse a 5-byte DF2 packet (75 Hz, compressed waveform).

    Byte layout: START(0x01), STATUS, PLETH, FLOAT, CHK
    STATUS bit 7 always set, bit 1 = SYNC (frame 1 of 25).
    FLOAT rotates through HR, SpO2, status across 25-frame cycle.
    CHK = (byte1 + byte2 + byte3 + byte4) mod 256.
    """
    global _df2_frame_counter
    if len(data) < 5:
        return None
    start = data[0]
    status = data[1]
    pleth = data[2]
    float_byte = data[3]
    chk = data[4]

    if (start + status + pleth + float_byte) & 0xFF != chk:
        return None

    # SYNC is bit 0 of STATUS (set on frame 1 only)
    if status & 0x01:
        _df2_frame_counter = 1
    else:
        _df2_frame_counter += 1

    frame_id = _df2_frame_counter

    result = {
        "pleth": pleth,
        "frame_id": frame_id,
    }

    # FLOAT byte per frame (range 0-127)
    if frame_id == 1:
        result["hr_msb"] = float_byte
    elif frame_id == 2:
        result["hr_lsb"] = float_byte
    elif frame_id == 3:
        result["spo2"] = float_byte if float_byte != 127 else None
    elif frame_id == 8:
        result["low_battery"] = bool(float_byte & 0x01)
        result["smartpoint"] = bool(float_byte & 0x20)
    elif frame_id == 9:
        result["spo2_display"] = float_byte if float_byte != 127 else None
    elif frame_id == 10:
        result["spo2_fast"] = float_byte if float_byte != 127 else None
    elif frame_id == 11:
        result["spo2_b2b"] = float_byte if float_byte != 127 else None
    elif frame_id == 14:
        result["e_hr_msb"] = float_byte
    elif frame_id == 15:
        result["e_hr_lsb"] = float_byte
    elif frame_id == 16:
        result["e_spo2"] = float_byte if float_byte != 127 else None
    elif frame_id == 20:
        result["hr_d_msb"] = float_byte
    elif frame_id == 21:
        result["hr_d_lsb"] = float_byte

    result["artifact"] = bool(status & 0x20)
    result["out_of_track"] = bool(status & 0x10)
    result["sensor_alarm"] = bool(status & 0x08)
    result["status_raw"] = status

    return result


def parse_df7_packet(data: bytes) -> dict:
    """Parse a 4-byte DF7 packet (75 Hz, full-resolution 16-bit waveform).

    Byte layout: STATUS1, PLETH_MSB, PLETH_LSB, FLOAT
    """
    if len(data) < 4:
        return None
    status1 = data[0]
    pleth = (data[1] << 8) | data[2]
    float_byte = data[3]

    frame_id = status1 & 0x1F

    result = {
        "pleth": pleth,
        "frame_id": frame_id,
        "status1_raw": status1,
    }

    if frame_id == 0:
        result["spo2_display"] = float_byte
    elif frame_id == 4:
        result["pr_display"] = float_byte

    # STATUS2 in FLOAT byte at frame 24
    if frame_id == 24:
        result["low_battery"] = bool(float_byte & 0x01)
        result["smartpoint"] = bool(float_byte & 0x20)

    return result


def parse_df8_packet(data: bytes) -> dict:
    """Parse a 4-byte DF8 packet (1 Hz).

    Byte layout: STATUS1, HR, SpO2, STATUS2
    STATUS1 bit 7 is always set.
    """
    if len(data) < 4:
        return None
    status1 = data[0]
    hr_byte = data[1]
    spo2_byte = data[2]
    status2 = data[3]

    pulse_rate = hr_byte if hr_byte != 127 else None
    spo2 = spo2_byte if spo2_byte != 127 else None

    return {
        "spo2": spo2,
        "pulse_rate": pulse_rate,
        "status1_raw": status1,
        "status2_raw": status2,
    }


def parse_df13_packet(data: bytes) -> dict:
    """Parse a DF13 spot-check measurement packet.

    Returns a single SmartPoint-qualified SpO2 and PR measurement.
    """
    if len(data) < 4:
        return None

    status = data[0]
    hr_msb = data[1]
    hr_lsb = data[2]
    spo2_byte = data[3]

    smartpoint = bool(status & 0x80)
    no_measurement = bool(status & 0x40)
    from_memory = bool(status & 0x20)
    low_battery = bool(status & 0x01)

    pulse_rate = ((hr_msb & 0x01) << 8) | hr_lsb
    spo2 = spo2_byte & 0x7F

    if pulse_rate == 511:
        pulse_rate = None
    if spo2 == 127:
        spo2 = None

    return {
        "spo2": spo2,
        "pulse_rate": pulse_rate,
        "smartpoint": smartpoint,
        "no_measurement": no_measurement,
        "from_memory": from_memory,
        "low_battery": low_battery,
        "status_raw": status,
    }


# Classic SPP Level 2 commands (ASCII framing)

def build_serial_get_config_command() -> bytes:
    return b"CFG?\r\n"


def build_serial_set_config_command(config_bytes: bytes) -> bytes:
    return b"CFG=" + config_bytes + b"\r\n"


def build_serial_get_datetime_command() -> bytes:
    return b"DTM?\r\n"


def build_serial_set_datetime_command(dt: datetime) -> bytes:
    ts = dt.strftime("%y%m%d%H%M%S").encode()
    return b"DTM=" + ts + b"\r\n"


def build_serial_memory_playback_command() -> bytes:
    return b"MPB?\r\n"


def build_serial_cancel_playback_command() -> bytes:
    return b"CAN!\r\n"


def build_serial_clear_memory_command() -> bytes:
    return b"MCL!\r\n"

