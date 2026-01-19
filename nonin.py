import asyncio
from datetime import datetime
from bleak import BleakClient

# CONFIG

DEVICE_ADDRESS = "08:6B:D7:13:01:E8"

NONIN_SERVICE_UUID        = "46A970E0-0D5F-11E2-8B5E-0002A5D5C51B"
CONTINUOUS_OXIM_UUID      = "0AAD7EA0-0D60-11E2-8E3C-0002A5D5C51B"
CONTROL_POINT_UUID        = "1447AF80-0D60-11E2-88B6-0002A5D5C51B"
DEVICE_STATUS_DF23_UUID   = "EC0A9302-4D24-11E7-B114-B2F933D5FE66"
PULSE_INTERVAL_DF20_UUID  = "34E27863-76FF-4F8E-96F1-9E3993AA6199"
PPG_DF22_UUID             = "EC0A883A-4D24-11E7-B114-B2F933D5FE66"


# GLOBAL STATE
last_control_command = None
last_parsed = {}
control_lock = asyncio.Lock()



STORAGE_RATES = {
    0x31: "1 second/sample",
    0x32: "2 seconds/sample",
    0x34: "4 seconds/sample",
}

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
    0x31: "Sensor Activation",
    0x32: "Programmed Time Activation",
    0x33: "Spot-Check Activation",
    0x34: "Bluetooth Connection Activation",
}

SECURITY_MODES = {
    0x01: "Security Mode 1",
    0x02: "Security Mode 2",
}

DISPLAY_MODES = {
    0x31: "Full Display",
    0x32: "Partial Display",
    0x33: "Memory Volume Indicator (MVI)",
}

DELETE_BOND_OPS = {
    0x00: "Delete all bonds",
    0x01: "Delete current collector bond",
    0x02: "Delete all except current collector bond",
}



# DATA PARSERS

def parse_continuous_oximetry(data: bytearray):
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
    pai_lso    = raw[1]
    pulse_time = int.from_bytes(raw[2:4], "big")

    bad_pulse = bool(status_mso & 0x80)
    pai_mso   = status_mso & 0x0F
    pai_raw   = (pai_mso << 8) | pai_lso
    pai_pct   = pai_raw / 100.0

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
    status  = payload[3]

    invalid_signal      = bool(status & 0x01)
    pulse_rate_too_high = bool(status & 0x02)

    pulses = []

    # If either status bit 0 or 1 is set, no pulse fields are present
    if not (invalid_signal or pulse_rate_too_high):
        offset = 4
        while offset + 4 <= len(payload) and len(pulses) < 6:
            pulse_raw = payload[offset:offset+4]
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
        "raw": payload,
    }


def parse_df22_payload(payload: bytes) -> dict:
    if len(payload) != DF22_EXPECTED_LENGTH:
        raise ValueError(
            f"DF22 invalid length: {len(payload)} (expected {DF22_EXPECTED_LENGTH})"
        )

    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(
            f"DF22 length mismatch: header={pkt_len}, actual={len(payload)}"
        )

    ppg_samples = []
    offset = 1

    for _ in range(25):
        sample = int.from_bytes(payload[offset:offset+2], "big", signed=False)
        ppg_samples.append(sample)
        offset += 2

    counter = int.from_bytes(payload[offset:offset+2], "big")

    return {
        "packet_length": pkt_len,
        "ppg_samples": ppg_samples,   # 25 samples
        "counter": counter,
        "raw": payload,
    }


def parse_df23_payload(payload: bytes) -> dict:
    if len(payload) < 7:
        raise ValueError(f"DF23 frame too short: {len(payload)} bytes")

    pkt_len = payload[0]
    if pkt_len != len(payload):
        raise ValueError(f"DF23 length mismatch: header={pkt_len}, actual={len(payload)}")

    sensor_type = payload[1]
    error_code  = payload[2]
    batt_volt   = payload[3]
    batt_pct    = payload[4]
    tx_index    = int.from_bytes(payload[5:7], "big")

    return {
        "packet_length": pkt_len,
        "sensor_type_raw": sensor_type,
        "sensor_type": DF23_SENSOR_TYPES.get(sensor_type, f"Unknown (0x{sensor_type:02X})"),
        "error_raw": error_code,
        "error": DF23_ERRORS.get(error_code, f"Unknown (0x{error_code:02X})"),
        "battery_voltage_raw": batt_volt,
        "battery_percentage": batt_pct,
        "tx_index": tx_index,
        "raw": payload,
    }


def parse_datetime_payload(payload: bytes):
    year   = int(payload[0:2].decode())
    month  = int(payload[2:4].decode())
    day    = int(payload[4:6].decode())
    hour   = int(payload[6:8].decode())
    minute = int(payload[8:10].decode())
    second = int(payload[10:12].decode())

    return datetime(2000 + year, month, day, hour, minute, second)


def parse_activation_mode_payload(payload: bytes):
    mode = payload[0]
    return mode, ACTIVATION_MODES.get(mode, f"Unknown (0x{mode:02X})")


def parse_turn_off_upon_disconnect_payload(payload: bytes):
    if payload[0] == 0x06:
        return True
    if payload[0] == 0x15:
        return False
    raise ValueError("Invalid TOUD ACK")


def parse_security_mode_response_byte(mode_byte: int):
    name = SECURITY_MODES.get(mode_byte, f"Unknown (0x{mode_byte:02X})")
    return mode_byte, name


def parse_display_mode_payload(payload: bytes):
    if len(payload) != 1:
        raise ValueError("Invalid Display Mode payload length")

    mode = payload[0]
    name = DISPLAY_MODES.get(mode, f"Unknown (0x{mode:02X})")
    return mode, name


def parse_device_id_payload(payload: bytes) -> str:
    if len(payload) != 50:
        raise ValueError("Invalid Device ID payload length")

    return payload.rstrip(b"\x00").decode("ascii", errors="strict")


def parse_cfg_time_ascii_10(raw: bytes) -> str:
    # Format: YYMMDDhhmm (10 ASCII)
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return raw.hex()


def encode_cfg_time_ascii_10(timestr: str) -> bytes:
    """
    Format must be exactly: 'YYMMDDhhmm' (10 ASCII chars)
    """
    if len(timestr) != 10 or not timestr.isdigit():
        raise ValueError("Time must be in 'YYMMDDhhmm' format")
    return timestr.encode("ascii")


def parse_config_block_payload(payload: bytes) -> dict:
    if len(payload) != 136:
        raise ValueError(f"Invalid CFG payload length: {len(payload)}")

    cfg = {}

    # 0-1: Reserved
    cfg["reserved_0_1"] = payload[0:2]

    # 2: Activation Option
    cfg["activation_option"] = payload[2]

    # 3: Storage Rate
    cfg["storage_rate"] = payload[3]

    # 4: Display Option
    cfg["display_option"] = payload[4]

    # 5-64: Programmed Time Windows
    cfg["start_time_1"] = parse_cfg_time_ascii_10(payload[5:15])
    cfg["stop_time_1"]  = parse_cfg_time_ascii_10(payload[15:25])

    cfg["start_time_2"] = parse_cfg_time_ascii_10(payload[25:35])
    cfg["stop_time_2"]  = parse_cfg_time_ascii_10(payload[35:45])

    cfg["start_time_3"] = parse_cfg_time_ascii_10(payload[45:55])
    cfg["stop_time_3"]  = parse_cfg_time_ascii_10(payload[55:65])

    # 65-114: Device Identification String (50 bytes)
    cfg["device_id"] = payload[65:115].rstrip(b"\x00").decode("ascii", "replace")

    # 115-118: Reserved
    cfg["reserved_115_118"] = payload[115:119]

    # 119-121: Software Revision (3 bytes)
    cfg["software_revision"] = payload[119:122]

    # 122-127: Software Revision Date (6 bytes)
    cfg["software_revision_date"] = payload[122:128]

    # 128-133: Reserved
    cfg["reserved_128_133"] = payload[128:134]

    # 134-135: Checksum
    cfg["checksum"] = int.from_bytes(payload[134:136], "big")

    # Verify Checksum: sum of bytes 0-133
    checksum_calc = sum(payload[0:134]) & 0xFFFF
    cfg["checksum_valid"] = (checksum_calc == cfg["checksum"])

    # Keep full raw block
    cfg["raw"] = payload

    return cfg


def parse_storage_rate_payload(payload: bytes):
    if len(payload) != 1:
        raise ValueError("Invalid Storage Rate payload length")

    rate = payload[0]
    name = STORAGE_RATES.get(rate, f"Unknown (0x{rate:02X})")
    return rate, name



# CONTROL POINT DISPATCHER

def control_point_handler(sender, data: bytearray):
    global last_control_command

    print("CONTROL RAW:", data.hex())

    if len(data) < 3:
        return

    opcode = data[0]

    # Set Security Mode Response: [E4, result]
    if opcode == 0xE4 and len(data) == 2:
        result = data[1]
        if last_control_command == "SET_SECURITY":
            if result == 0x00:
                print("SET_SECURITY succeeded")
            else:
                print(f"SET_SECURITY failed (result=0x{result:02X})")
            last_control_command = None
            return
        # Unknown context, still log:
        print(f"Unexpected SET_SECURITY response context (result=0x{result:02X})")
        return

    # Get Security Mode Response: [E5, mode]
    if opcode == 0xE5 and len(data) == 2:
        mode_byte = data[1]
        mode, name = parse_security_mode_response_byte(mode_byte)
        if last_control_command == "GET_SECURITY":
            print(f"Security Mode: {name} (0x{mode:02X})")
            last_control_command = None
            return
        # Unknown context, still informative:
        print(f"Unmatched GET_SECURITY response: {name} (0x{mode:02X})")
        return


    # DELETE BOND RESPONSE (0xE3)
    if opcode == 0xE3 and len(data) == 2:
        result = data[1]
    
        if last_control_command == "DELETE_BOND":
            if result == 0x00:
                print("DELETE_BOND succeeded")
            else:
                print("DELETE_BOND failed")
    
            last_control_command = None
            return
    
        print("Unmatched DELETE_BOND response:", data.hex())
        return


    result = data[1]
    length = data[2]
    payload = data[3:3+length]

    if opcode != 0xE0:
        return

    if result == 0x02:
        print("Device busy")
        return

    if result != 0x00:
        print("Command failed")
        return

    if len(payload) != length:
        print("Length mismatch")
        return

    # Date / Time
    if last_control_command == "GET_DATETIME":
        if length == 12:
            try:
                dt = parse_datetime_payload(payload)
                print("Device Date/Time:", dt)
            except ValueError as e:
                print("Date/Time parse error:", e)
        else:
            print("Unexpected GET_DATETIME payload length:", length)

        last_control_command = None
        return

    if last_control_command == "SET_DATETIME":
        if length == 1 and payload[0] == 0x06:
            print("SET_DATETIME acknowledged")
        else:
            print("Unexpected SET_DATETIME response:", payload.hex())

        last_control_command = None
        return

    # Activation Mode
    if last_control_command == "GET_ACTIVATION":
        if length == 1:
            try:
                mode, name = parse_activation_mode_payload(payload)
                print(f"Activation Mode: {name} (0x{mode:02X})")
            except ValueError as e:
                print("Activation Mode parse error:", e)
        else:
            print("Unexpected GET_ACTIVATION payload length:", length)
    
        last_control_command = None
        return
    
    if last_control_command == "SET_ACTIVATION":
        if length == 1 and payload[0] == 0x06:
            print("SET_ACTIVATION acknowledged")
        else:
            print("Unexpected SET_ACTIVATION response:", payload.hex())
    
        last_control_command = None
        return

    if last_control_command == "TURN_OFF_UPON_DISCONNECT":
        if length == 1:
            try:
                ack = parse_turn_off_upon_disconnect_payload(payload)
                print("Turn off upon disconnect:", "ACK" if ack else "NACK")
            except ValueError as e:
                print("TOUD parse error:", e)
        else:
            print("Unexpected TOUD payload length:", length)
    
        last_control_command = None
        return

    # Security Mode
    if last_control_command == "GET_SECURITY":
        if length == 1:
            try:
                mode, name = parse_security_mode_payload(payload)
                print(f"Security Mode: {name} (0x{mode:02X})")
            except ValueError as e:
                print("Security Mode parse error:", e)
        else:
            print("Unexpected GET_SECURITY payload length:", length)
    
        last_control_command = None
        return
    
    if last_control_command == "SET_SECURITY":
        if length == 1 and payload[0] == 0x06:
            print("SET_SECURITY acknowledged")
        else:
            print("Unexpected SET_SECURITY response:", payload.hex())
    
        last_control_command = None
        return

    # Display Mode
    if last_control_command == "GET_DISPLAY":
        if length == 1:
            try:
                mode, name = parse_display_mode_payload(payload)
                print(f"Display Mode: {name} (0x{mode:02X})")
            except ValueError as e:
                print("Display Mode parse error:", e)
        else:
            print("Unexpected GET_DISPLAY payload length:", length)
    
        last_control_command = None
        return
    
    if last_control_command == "SET_DISPLAY":
        if length == 1 and payload[0] == 0x06:
            print("SET_DISPLAY acknowledged")
        else:
            print("Unexpected SET_DISPLAY response:", payload.hex())
    
        last_control_command = None
        return


    # Device Identification String
    if last_control_command == "GET_DEVICE_ID":
        if length == 50:
            try:
                text = parse_device_id_payload(payload)
                print(f"Device ID String: '{text}'")
            except ValueError as e:
                print("Device ID parse error:", e)
        else:
            print("Unexpected GET_DEVICE_ID payload length:", length)
    
        last_control_command = None
        return
    
    
    if last_control_command == "SET_DEVICE_ID":
        if length == 1 and payload[0] == 0x06:
            print("SET_DEVICE_ID acknowledged")
        else:
            print("Unexpected SET_DEVICE_ID response:", payload.hex())
    
        last_control_command = None
        return


    # Clear Memory
    if last_control_command == "CLEAR_MEMORY":
        if length == 1:
            ack = payload[0]
            if ack == 0x06:
                print("CLEAR_MEMORY acknowledged (success)")
            elif ack == 0x15:
                print("CLEAR_MEMORY NACK (failure)")
            else:
                print(f"CLEAR_MEMORY unexpected ack byte: 0x{ack:02X}")
        else:
            print("CLEAR_MEMORY unexpected payload length:", length)
    
        last_control_command = None
        return


    # Storage Rate
    if last_control_command == "GET_STORAGE_RATE":
        if length == 1:
            try:
                rate, name = parse_storage_rate_payload(payload)
                print(f"Storage Rate: {name} (0x{rate:02X})")
            except ValueError as e:
                print("Storage Rate parse error:", e)
        else:
            print("Unexpected GET_STORAGE_RATE payload length:", length)
    
        last_control_command = None
        return
    
    
    if last_control_command == "SET_STORAGE_RATE":
        if length == 1 and payload[0] == 0x06:
            print("SET_STORAGE_RATE acknowledged")
        else:
            print("Unexpected SET_STORAGE_RATE response:", payload.hex())
    
        last_control_command = None
        return


    # Configuration Block (CFG)
    if last_control_command == "GET_CONFIG":
        if length == 136:
            try:
                cfg = parse_config_block_payload(payload)
    
                print("Configuration Block:")
                print(f"   Activation Option: 0x{cfg['activation_option']:02X}")
                print(f"   Storage Rate:      0x{cfg['storage_rate']:02X}")
                print(f"   Display Option:    0x{cfg['display_option']:02X}")
    
                print(f"   Start 1: {cfg['start_time_1']}  Stop 1: {cfg['stop_time_1']}")
                print(f"   Start 2: {cfg['start_time_2']}  Stop 2: {cfg['stop_time_2']}")
                print(f"   Start 3: {cfg['start_time_3']}  Stop 3: {cfg['stop_time_3']}")
    
                print(f"   Device ID: '{cfg['device_id']}'")
                print(f"   Software Rev: {cfg['software_revision'].hex()}")
                print(f"   Software Date: {cfg['software_revision_date'].hex()}")
                print(f"   Checksum OK: {cfg['checksum_valid']}")
    
            except ValueError as e:
                print("CFG parse error:", e)
        else:
            print("Unexpected GET_CONFIG payload length:", length)
    
        last_control_command = None
        return

    # Set Configuration
    if last_control_command == "SET_CONFIG":
        if length == 1 and payload[0] == 0x06:
            print("SET_CONFIGURATION acknowledged")
        else:
            print("Unexpected SET_CONFIGURATION response:", payload.hex())
    
        last_control_command = None
        return

    last_control_command = None



# CONTROL COMMAND BUILDERS

def build_get_datetime_command():
    return bytes([
        0x60, 0x4E, 0x4D, 0x49, 0x06,
        0x44, 0x54, 0x4D, 0x3F,
        0x0D, 0x0A
    ])

def build_set_datetime_command(dt: datetime):
    ts = dt.strftime("%y%m%d%H%M%S").encode()
    return bytes([
        0x60, 0x4E, 0x4D, 0x49, 0x12,
        0x44, 0x54, 0x4D, 0x3D
    ]) + ts + bytes([0x0D, 0x0A])

def build_get_activation_mode_command():
    return bytes([
        0x60, 0x4E, 0x4D, 0x49, 0x06,
        0x41, 0x43, 0x54, 0x3F,
        0x0D, 0x0A
    ])

def build_set_activation_mode_command(mode: int):
    return bytes([
        0x60, 0x4E, 0x4D, 0x49, 0x07,
        0x41, 0x43, 0x54, 0x3D,
        mode,
        0x0D, 0x0A
    ])

def build_turn_off_upon_disconnect_command():
    return bytes([
        0x60, 0x4E, 0x4D, 0x49, 0x06,
        0x54, 0x4F, 0x46, 0x21,
        0x0D, 0x0A
    ])

def build_get_security_mode_command():
    return bytes([
        0x65,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
    ])

def build_set_security_mode_command(mode: int):
    if mode not in SECURITY_MODES:
        raise ValueError("Invalid security mode")

    return bytes([
        0x64,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
        mode
    ])

def build_set_display_mode_command(mode: int) -> bytes:
    """
    mode:
      0x31 = Full Display
      0x32 = Partial Display
      0x33 = Memory Volume Indicator
    """
    if mode not in DISPLAY_MODES:
        raise ValueError("Invalid display mode")

    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
        0x07,                   # Command Length
        0x44, 0x49, 0x53,       # 'D' 'I' 'S'
        0x3D,                   # '='
        mode,                   # Display Mode
        0x0D, 0x0A              # CR LF
    ])


def build_get_display_mode_command() -> bytes:
    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
        0x06,                   # Command Length
        0x44, 0x49, 0x53,       # 'D' 'I' 'S'
        0x3F,                   # '?'
        0x0D, 0x0A              # CR LF
    ])


def build_set_device_id_command(text: str) -> bytes:
    raw = text.encode("ascii", errors="strict")

    if len(raw) > 50:
        raise ValueError("Device ID string must be <= 50 ASCII characters")

    padded = raw.ljust(50, b'\x00')

    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N''M''I'
        0x38,                   # Command Length (56)
        0x49, 0x44, 0x53,       # 'I''D''S'
        0x3D,                   # '='
    ]) + padded + bytes([
        0x0D, 0x0A              # CR LF
    ])


def build_get_device_id_command() -> bytes:
    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N''M''I'
        0x06,                   # Command Length
        0x49, 0x44, 0x53,       # 'I''D''S'
        0x3F,                   # '?'
        0x0D, 0x0A              # CR LF
    ])


def build_get_config_block_command() -> bytes:
    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
        0x06,                   # Command Length
        0x43, 0x46, 0x47,       # 'C' 'F' 'G'
        0x3F,                   # '?'
        0x0D, 0x0A              # CR LF
    ])


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
    """
    Builds the full SET_CONFIGURATION command using the exact table layout.

    device_id: max 50 ASCII chars
    software_revision: 3 bytes
    software_revision_date: 6 bytes
    """

    # Build 136-byte CFG payload (bytes 9..144)

    payload = bytearray(136)

    # 0-1: Reserved
    payload[0:2] = b"\x00\x00"

    # 2: Activation Option
    payload[2] = activation_option

    # 3: Storage Rate
    payload[3] = storage_rate

    # 4: Display Option
    payload[4] = display_option

    # 5-14: Start Time 1
    payload[5:15] = encode_cfg_time_ascii_10(start_time_1)

    # 15-24: Stop Time 1
    payload[15:25] = encode_cfg_time_ascii_10(stop_time_1)

    # 25-34: Start Time 2
    payload[25:35] = encode_cfg_time_ascii_10(start_time_2)

    # 35-44: Stop Time 2
    payload[35:45] = encode_cfg_time_ascii_10(stop_time_2)

    # 45-54: Start Time 3
    payload[45:55] = encode_cfg_time_ascii_10(start_time_3)

    # 55-64: Stop Time 3
    payload[55:65] = encode_cfg_time_ascii_10(stop_time_3)

    # 65-114: Device Identification String (50 bytes, null-padded)
    raw_id = device_id.encode("ascii", errors="strict")
    if len(raw_id) > 50:
        raise ValueError("Device ID must be <= 50 ASCII characters")
    payload[65:115] = raw_id.ljust(50, b"\x00")

    # 115-118: Reserved
    payload[115:119] = b"\x00" * 4

    # 119-121: Software Revision  (must be zero)
    payload[119:122] = b"\x00\x00\x00"

    # 122-127: Software Revision Date (must be zero)
    payload[122:128] = b"\x00" * 6

    # 128-133: Reserved
    payload[128:134] = b"\x00" * 6

    # 134-135: Checksum (sum of bytes 0-133)
    checksum = sum(payload[0:134]) & 0xFFFF
    payload[134:136] = checksum.to_bytes(2, "big")

    # Build full 147-byte SET command
    frame = bytes([
        0x60,                   # 0: Opcode
        0x4E, 0x4D, 0x49,       # 1-3: 'N' 'M' 'I'
        0x8D,                   # 4: Command Length (141)
        0x43, 0x46, 0x47,       # 5-7: 'C' 'F' 'G'
        0x3D,                   # 8: '='
    ]) + payload + bytes([
        0x0D,                   # 145: CR
        0x0A,                   # 146: LF
    ])

    if len(frame) != 147:
        raise RuntimeError(f"SET_CONFIGURATION frame size is {len(frame)}, expected 147")

    return frame


def build_delete_bond_command(operation: int) -> bytes:
    if operation not in DELETE_BOND_OPS:
        raise ValueError("Invalid delete bond operation")

    return bytes([
        0x63,             # Opcode
        0x4E, 0x4D, 0x49, # 'N' 'M' 'I'
        operation,        # Operation
    ])


def build_clear_memory_command() -> bytes:
    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
        0x06,                   # Command Length
        0x4D, 0x43, 0x4C,       # 'M' 'C' 'L'
        0x21,                   # '!'
        0x0D, 0x0A              # CR LF
    ])


def build_set_storage_rate_command(rate: int) -> bytes:
    if rate not in STORAGE_RATES:
        raise ValueError("Invalid storage rate")

    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
        0x07,                   # Command Length
        0x44, 0x53, 0x52,       # 'D' 'S' 'R'
        0x3D,                   # '='
        rate,                   # Storage Rate
        0x0D, 0x0A              # CR LF
    ])


def build_get_storage_rate_command() -> bytes:
    return bytes([
        0x60,                   # Opcode
        0x4E, 0x4D, 0x49,       # 'N' 'M' 'I'
        0x06,                   # Command Length
        0x44, 0x53, 0x52,       # 'D' 'S' 'R'
        0x3F,                   # '?'
        0x0D, 0x0A              # CR LF
    ])



# CONTROL COMMAND REGISTRY

CONTROL_COMMANDS = {
    "GET_DATETIME": lambda: build_get_datetime_command(),
    "SET_DATETIME": lambda dt: build_set_datetime_command(dt),
    "GET_ACTIVATION": lambda: build_get_activation_mode_command(),
    "SET_ACTIVATION": lambda mode: build_set_activation_mode_command(mode),
    "TURN_OFF_UPON_DISCONNECT": lambda: build_turn_off_upon_disconnect_command(),
    "GET_SECURITY": lambda: build_get_security_mode_command(),
    "SET_SECURITY": lambda mode: build_set_security_mode_command(mode),
    "GET_DISPLAY": lambda: build_get_display_mode_command(),
    "SET_DISPLAY": lambda mode: build_set_display_mode_command(mode),
    "GET_DEVICE_ID": lambda: build_get_device_id_command(),
    "SET_DEVICE_ID": lambda text: build_set_device_id_command(text),
    "GET_CONFIG": lambda: build_get_config_block_command(),
    "SET_CONFIG": lambda **kwargs: build_set_configuration_command(**kwargs),
    "DELETE_BOND": lambda operation: build_delete_bond_command(operation),
    "CLEAR_MEMORY": lambda: build_clear_memory_command(),
    "GET_STORAGE_RATE": lambda: build_get_storage_rate_command(),
    "SET_STORAGE_RATE": lambda rate: build_set_storage_rate_command(rate),
}

# SAFE CONTROL CALLER

async def send_control_command(client, name, *args):
    global last_control_command

    if name not in CONTROL_COMMANDS:
        raise ValueError("Unknown control command")

#    if not last_parsed.get("flags", {}).get("encrypted", False):
#        raise RuntimeError("Link not encrypted")

    async with control_lock:
        await asyncio.sleep(0.4)
        cmd = CONTROL_COMMANDS[name](*args)
        last_control_command = name
        print("Sending:", name)
        await client.write_gatt_char(CONTROL_POINT_UUID, cmd)

# OXIMETRY HANDLER

def oximetry_handler(sender, data):
    global last_parsed
    parsed = parse_continuous_oximetry(data)
    last_parsed = parsed
    print("OXIMETRY:", parsed)


def df23_handler(sender, data: bytearray):
    try:
        parsed = parse_df23_payload(data)

        print(
            "DF23 STATUS:",
            {
                "sensor": parsed["sensor_type"],
                "error": parsed["error"],
                "battery_%": parsed["battery_percentage"],
                "battery_raw": parsed["battery_voltage_raw"],
                "tx_index": parsed["tx_index"],
            }
        )

        # Optional: trigger alarms / reconnects
        if parsed["error_raw"] != 0x00:
            print("DEVICE ERROR:", parsed["error"])

    except ValueError as e:
        print("DF23 parse error:", e, "RAW:", data.hex())


def df20_handler(sender, data: bytearray):
    try:
        parsed = parse_df20_payload(data)

        print(
            f"DF20 PULSE: counter={parsed['counter']} "
            f"invalid={parsed['invalid_signal']} "
            f"rate_high={parsed['pulse_rate_too_high']} "
            f"pulses={parsed['pulse_count']}"
        )

        for i, p in enumerate(parsed["pulses"], 1):
            print(
                f"  Pulse {i}: "
                f"PAI={p['pai_percent']:.2f}% "
                f"Interval={p['pulse_interval_ms']:.1f} ms "
                f"{'BAD' if p['bad_pulse'] else 'OK'}"
            )

    except ValueError as e:
        print("DF20 parse error:", e, "RAW:", data.hex())


def df22_handler(sender, data: bytearray):
    try:
        parsed = parse_df22_payload(data)

        samples = parsed["ppg_samples"]
        counter = parsed["counter"]

        print(
            f"DF22 PPG: counter={counter} "
            f"samples[0]={samples[0]} "
            f"samples[-1]={samples[-1]}"
        )

        # print("PPG:", samples)

    except ValueError as e:
        print("DF22 parse error:", e, "RAW:", data.hex())



# MAIN

async def main():
    print("Connecting...")
    client = BleakClient(DEVICE_ADDRESS, timeout=50.0)
    await client.connect()
    print("Connected")

    await client.start_notify(CONTROL_POINT_UUID, control_point_handler)
    
    await client.start_notify(CONTINUOUS_OXIM_UUID, oximetry_handler)
    await client.start_notify(PULSE_INTERVAL_DF20_UUID, df20_handler)
    await client.start_notify(PPG_DF22_UUID, df22_handler)  
    await client.start_notify(DEVICE_STATUS_DF23_UUID, df23_handler)

    await send_control_command(client, "SET_DATETIME", datetime.now())
    await send_control_command(client, "GET_DATETIME")

    #await send_control_command(client, "SET_ACTIVATION", 0x34)
    await send_control_command(client, "GET_ACTIVATION")

    await send_control_command(client, "GET_SECURITY")

    await send_control_command(client, "GET_DISPLAY")

    #await send_control_command(client, "SET_DEVICE_ID", "WristOx1234")
    await send_control_command(client, "GET_DEVICE_ID")

    await send_control_command(client, "GET_STORAGE_RATE")

    await send_control_command(client, "GET_CONFIG")


    # await send_control_command(client, "TURN_OFF_UPON_DISCONNECT")

    print("Streaming...")
    while True:
        await asyncio.sleep(1)

asyncio.run(main())

