# datasabi-probe (Windows test program)

A small command-line program used to test the Windows plan before the Windows collector is built. It is not part of the collector and is not shipped to users.

## What it does

- Counts the bytes each process sends and receives, using the ETW provider `Microsoft-Windows-Kernel-Network`.
- Labels `svchost.exe` processes with the services they host, such as `wuauserv` (Windows Update) or `DoSvc` (Delivery Optimization).
- Compares the total with the network adapters' own byte counters.
- Prints the top apps every minute and saves a CSV report next to the program when it stops.

## Privacy

Addresses are only looked at in memory, to skip loopback and local-network traffic. The report holds process names, service names and byte counts. It contains no addresses, website names or packet contents, and not the network's name.

## How to run

1. Download `datasabi-probe.exe` from the "Windows probe" workflow run (Actions tab, Artifacts).
2. Open PowerShell as Administrator, then go to the folder with the program.
3. Run `.\datasabi-probe.exe`, or `.\datasabi-probe.exe --minutes 30` for a shorter run.
4. Press Enter to stop early. The report is saved as `datasabi-probe-<number>.csv` in the same folder.

The program isn't signed, so Windows may warn before it runs.

If it says the trace couldn't start because a previous run crashed, run `logman stop DataSabiProbe -ets` and try again.
