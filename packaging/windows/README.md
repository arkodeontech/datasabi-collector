# Windows packaging (planned)

The Windows collector will be a Windows service (`DataSabiCollector`, LocalSystem)
that reads per-process network bytes from ETW (Microsoft-Windows-Kernel-Network)
and serves the same protocol over the named pipe `\\.\pipe\datasabi-collector`.

`collector.wxs` is the WiX v4 fragment the DataSabi MSI will include to install
and start the service. It is not used by any build yet.

The program can also register itself, which is what an installer without WiX
service support uses (run as administrator):

    datasabi-collector install     # start with Windows, restart on failure, start now
    datasabi-collector uninstall   # stop and remove; the usage history is kept

`install` refuses a program outside `%ProgramFiles%`: the service runs as
LocalSystem, so whoever can replace its file controls the PC. The installer must
therefore install per-machine (Program Files), not per-user. `install --dev`
allows any folder, with a warning, for tests only.

The Service Control Manager runs it as `datasabi-collector service`. Its data
(`usage.db`) and logs (`logs\collector.log`, rolled over at 5 MB, 3 kept) are in
`%ProgramData%\DataSabi`, readable only by SYSTEM and Administrators.
