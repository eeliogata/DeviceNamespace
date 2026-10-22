# DeviceNamespace

Compares opens of a device object and a name below it. The two `NtCreateFile` calls use the same access mask, share mode and open options. The program does not send IOCTLs.

```
DeviceNamespace.exe \Device\Name [--access 0x1] [--child name]
```

`--access` defaults to `FILE_READ_DATA` (`0x1`). `SYNCHRONIZE` is added for synchronous opens; both the requested and effective masks are printed. The child name defaults to `dn_probe` and must be a single path component.

Build x64 with CMake:

```
cmake -S . -B build -A x64
cmake --build build --config Release
```

Run it as a standard user when checking an access boundary. A denied root open and a successful child open is a lead. Confirm that the child handle reaches the intended driver and that the driver exposes a sensitive operation before treating it as a vulnerability. Device type and characteristics are shown when the driver supports `FileFsDeviceInformation`.

[Windows device namespace access rules](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/controlling-device-namespace-access)
