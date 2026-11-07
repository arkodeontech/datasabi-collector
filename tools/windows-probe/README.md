# datasabi-probe (Windows test program)

A small command-line program used to test the Windows plan before the Windows collector is built. It is not part of the collector and is not shipped to users.

## What it does

- Counts the bytes each process sends and receives, using the ETW provider `Microsoft-Windows-Kernel-Network`.
- Labels `svchost.exe` processes with the services they host, such as `wuauserv` (Windows Update) or `DoSvc` (Delivery Optimization).
- Compares the total with the byte and packet counters of the adapter that carries the internet connection. Packets include headers, so the gap between the two can be estimated.
- Records how many events the trace lost, from `logman query DataSabiProbe -ets`, so a low match can be told apart from lost events.
- Prints the top apps every minute and saves a CSV report next to the program when it stops.

## Privacy

Addresses are only looked at in memory, to skip loopback and local-network traffic. The report holds process names, service names, adapter names and counts. It contains no addresses, website names or packet contents, and the network's name is neither printed nor saved.

## How to run

1. Download `datasabi-probe.exe` from the "Windows probe" workflow run (Actions tab, Artifacts).
2. Open PowerShell as Administrator, then go to the folder with the program.
3. Run `.\datasabi-probe.exe`, or `.\datasabi-probe.exe --minutes 30` for a shorter run.
4. Press Enter to stop early. The report is saved as `datasabi-probe-<number>.csv` in the same folder.

The program isn't signed, so Windows may warn before it runs. If Windows blocks it, run `Unblock-File .\datasabi-probe.exe` first.

## Measured runs

- **Only this computer on the MiFi or hotspot.** Disconnect every other device (phones, other laptops, TVs), and keep only one connection active on the computer (no cable or second Wi-Fi). Don't switch networks during a run; start a new run for each connection.
- **Download a file of known size,** 200 MB is enough (500 MB is optional), and click Check for updates in Windows Update.
- **Note the data used before and after,** from as many of these as you have:
  - the MiFi's own usage counter on its admin page (often 192.168.0.1 or 192.168.8.1)
  - the balance in the network's app or by USSD; read it about 10 minutes after the run ends, because it updates late and is rounded
  - on a phone hotspot: the phone's hotspot usage figure (on Android, usually Settings, then Data usage, then Hotspot), not the balance, because the phone's own apps use the same data

The program clears a session left by a crashed run before it starts. If the trace still won't start, run `logman stop DataSabiProbe -ets` and try again.
