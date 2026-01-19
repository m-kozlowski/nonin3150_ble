Proof of concept for the Nonin wristox2 3150 configuration tool via BLE

This script is a Python BLE control client for Nonin pulse oximeters that implements the Nonin NMI configuration protocol over Bluetooth LE.
## Supported control features
- Get / set device date & time
- Get / set activation mode (sensor, programmed time, Bluetooth, spot-check)
- Get / set display mode
- Get / set storage rate
- Read and write the full 136-byte configuration block (with checksum validation)
- Read / set device identification string
- Delete BLE bonds
- Clear internal device memory
- Enable “turn off upon disconnect”

Streams live SpO₂, pulse rate, PAI, pulse intervals, and raw PPG waveform\
Parses multiple proprietary Nonin data frames (DF20 / DF22 / DF23)
