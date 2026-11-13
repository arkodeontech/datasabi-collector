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
`%ProgramData%\DataSabi`, owned by Administrators and readable only by SYSTEM
and Administrators. Any user can create folders in `%ProgramData%`, so a
`DataSabi` or `logs` folder that is a junction or symlink, or isn't owned by
SYSTEM or Administrators, is moved aside (`DataSabi.untrusted-<unix time>`) and
made fresh. The database and log files are moved aside too if they are links,
have extra hard links, or aren't owned by SYSTEM or Administrators.

If the service stops with an error, its exit code (`sc query DataSabiCollector`,
`SERVICE_EXIT_CODE`) says where: 1 while running (see the log), 2 the data folder
couldn't be prepared, 3 the log file couldn't be opened. Codes 2 and 3 happen
before the log is open.
