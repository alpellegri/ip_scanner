0. General Requirements and Structure
[R0] Requirements must have an identifier with prefix R followed by a number, and optionally a dot with a secondary number. Gaps in numbering are allowed.
[R0.1] The code must include, in comments, the indication of the implemented requirements.
[R0.2] The code must include test cases for each requirement, with comments indicating the verified requirements.

1. Requirements related to scanning functions
[R1] The system must scan a local IP range, configurable as a single IP (e.g., 192.168.1.11) or a range (e.g., 192.168.1.1-254). Multiple ranges or CIDR notation are not supported.
[R1.0] The system shall be able to use scanner tool: nmap or arp-scan plus nping.
[R2] The status for each device is one of: Online: responds to the scanner tool in the current scan. Offline: does not respond to the scanner tool. A device found active must remain so until a subsequent scan confirms its absence. Offline devices must not be reported to standard output.
[R2.1] any request cannot take more that SCAN_TIMEOUT (ms).
[R5] Devices responding to the scanner tool must be displayed in standard output in the format: IP <IP address>: OK, MAC: <MAC address>, hostname, manufacturer, latency.
[R16] Support multithreading or multiprocessing to speed up the scan.
[R14] Configuration via config.json must include: IP range (e.g., string “192.168.1.1-254”), scan SCAN_TIMEOUT (ms), SCAN_PERIOD period (0 for one-shot, ≥30 for periodic), threads/processes, webui poll_interval (min 30s) including the type of scanner tool: nmap or arp-scanner. The system must validate values and support hot-reload upon configuration changes. On dynamic change of SCAN_PERIOD: from 0 to >0: immediately start periodic scans; On dynamic change of SCAN_PERIOD: from >0 to 0: immediately stop the current scan, perform a new one, then go idle.
[R29] At startup, if SCAN_PERIOD > 0, automatically start periodic scans.
[R29.1] If SCAN_PERIOD = 0, perform a one-shot scan and then stay idle.

2. Requirements related to data storage
[R25] hosts.json must contain, for each device that responded to the scanner tool: IP, MAC, hostname (if available), manufacturer (if available), assigned name (if available), and timestamp of last scan. The user-assigned name has priority over hostname and is preserved regardless of device status. A device is updated as online only if it responds to the scanner tool. An existing device becomes offline if it does not respond to the scanner tool. it is a map with mac as key. Example:
{
  "b8:27:eb:fc:2d:bd": {
    "ip": ["192.168.1.3", "192.168.1.8"],
    "hostname": "omv-rbpi2",
    "manufacturer": "Raspberry Pi Foundation",
    "name": "nas",
    "last_seen": 1759167534
  },
  "aa:bb:cc:dd:ee:ff": {
    "ip": ["192.168.1.4"],
    "hostname": "pc-ufficio",
    "manufacturer": "Dell",
    "name": "ufficio",
    "last_seen": 1759168000
  }
}

3. Requirements related to frontend visualization
[R24] The Web UI must display the device table stored in hosts.json (online and offline). Data is updated via polling on the /api/v1/hosts endpoint, with interval set by poll_interval.
[R24.0] The Web UI must display first online devices ordered by ip, then offline devices ordered by last_seen.
[R24.1] An interface must be provided to modify the configuration.
[R24.2] An interface must be provided to remove devices from hosts.json.
[R26] The Web UI must clearly indicate the online/offline status of each device.
[R28] The Web UI must allow assigning custom names to devices. A Save button must be used to store the device name.
[R28.1] The Web UI must be implemented in two distinct files: index.html and app.js.
[R13] For each device in the hosts table: if a device is active, the Web UI must show the last latency; if a device is not active, the Web UI must show the timestamp of the last scan when it was active.

4. Requirements related to backend and API
[R27] The server must be developed in typescript for both scanning and the Web UI.
[R27.1] The server must output scan results to standard output without interactivity via standard input.
[R27.2] Configuration must occur exclusively via config.json; CLI parameters are not allowed.
[R32] The server must be implemented only in two files: main.ts and scanner.ts, organized into internal modules for clarity and modularity.
[R30] A REST API must be implemented with the following main endpoints:

### /api/v1/config (GET to read, PUT to update configuration)

### /api/v1/hosts (GET full list, PATCH for partial updates, DELETE to remove devices)

Formato della risposta GET /api/v1/hosts:
```json
{
  "<mac_address>": {
    "ip": ["<ip_address>", ...],
    "hostname": "<string>",
    "manufacturer": "<string>",
    "name": "<string>",
    "last_seen": <number>,
    "status": "<string>",
    "latency": <number>
  },
  ...
}
```

### /api/v1/status (GET for server status and last scan)

The backend manages reading and writing of the configuration: config.json file.

5. Error handling requirements
[R34] Non-critical network errors (e.g., timeouts, disconnections) must not interrupt scanning. If the hosts.json file is corrupted, the server must create a new empty one and continue execution.
[R35] At startup, the server must verify the availability of necessary privileges (e.g., root permissions). In case of insufficient permissions or critical errors, it must notify the user (console or UI) and terminate execution without automatic recovery attempts.

6. Build requirements
[R36] Build must not produce warnings.
[R37] The tree must be organized to separate program files from data.
[R38] Program files must be stored in the src folder. config.json and hosts.json must be stored in the data folder.
[R39] Folders src and data must be at the same level.

7. Docker requirements
[R40] A Docker image must be created with src and data separated.
[R41] A docker-compose file must be created.
[R42] A .dockerignore file must be created to exclude temporary build files.
[R43] A Makefile must be created for building the program and generating the Docker image.
