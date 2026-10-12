# Windows packaging (planned)

The Windows collector will be a Windows service (`DataSabiCollector`, LocalSystem)
that reads per-process network bytes from ETW (Microsoft-Windows-Kernel-Network)
and serves the same protocol over the named pipe `\\.\pipe\datasabi-collector`.

`collector.wxs` is the WiX v4 fragment the DataSabi MSI will include to install
and start the service. It is not used by any build yet.
