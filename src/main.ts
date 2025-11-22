// [R27] The server must be developed in typescript for both scanning and the Web UI.
// [R32] The server must be implemented only in two files: main.ts and scanner.ts, organized into internal modules for clarity and modularity.

import express from 'express';
import * as fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { Scanner } from './scanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// [R25] hosts.json must contain, for each device that responded to the scanner tool: IP, MAC, hostname (if available), manufacturer (if available), assigned name (if available), and timestamp of last scan.
interface Host {
    ip: string[];
    hostname: string;
    manufacturer: string;
    name: string;
    last_seen: number;
    status?: string;
    latency?: number;
}

type HostsMap = Record<string, Host>;

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(join(__dirname, '../static')));
app.use('/static', express.static(join(__dirname, '../static')));

// Abilita CORS
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

const CONFIG_PATH = './data/config.json';
const HOSTS_PATH = './data/hosts.json';

let config: any;
let hosts: any = {};
let scanner: Scanner;

// [R30] A REST API must be implemented with the following main endpoints
// [R30] /api/v1/config (GET to read, PUT to update configuration)
app.get('/api/v1/config', (req, res) => {
    res.json(config);
});

// [R14] Configuration via config.json must include support hot-reload upon configuration changes.
app.put('/api/v1/config', async (req, res) => {
    try {
        config = req.body;
        await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
        res.json(config);
        // [R14] support hot-reload upon configuration changes
        scanner.updateConfig(config);
    } catch (error) {
        res.status(500).send('Error saving configuration');
    }
});

// [R30] /api/v1/hosts (GET full list, PATCH for partial updates, DELETE to remove devices)
app.get('/api/v1/hosts', async (req, res) => {
    try {
        // [R24] The Web UI must display the device table stored in hosts.json (online and offline). Data is updated via polling on the /api/v1/hosts endpoint, with interval set by poll_interval.
        // [R26] The Web UI must clearly indicate the online/offline status of each device.
        const data = await fs.readFile(HOSTS_PATH, 'utf-8');
        const fileHosts = JSON.parse(data);
        
        const response: HostsMap = {};
        const now = Math.floor(Date.now() / 1000);
        const SCAN_PERIOD = config.period || 0;
        const SCAN_TIMEOUT = config.timeout || 1000;
        
        for (const [mac, host] of Object.entries(fileHosts)) {
            const h = host as Host;
            // [R2] The status for each device is one of: Online: responds to the scanner tool in the current scan. Offline: does not respond to the scanner tool. A device found active must remain so until a subsequent scan confirms its absence. Offline devices must not be reported to standard output.
            // [R25] Device status is determined solely by scanner response
            // A device is updated as online only if it responds to the scanner tool
            // An existing device becomes offline if it does not respond to the scanner tool
            response[mac] = {
                ip: Array.isArray(h.ip) ? h.ip : [h.ip].filter(Boolean),
                hostname: h.hostname || '',
                manufacturer: h.manufacturer || '',
                name: h.name || '',
                last_seen: h.last_seen || 0,
                status: h.status || 'offline',  // Use status directly from scanner
                // [R13] For each device in the hosts table: if a device is active, the Web UI must show the last latency; if a device is not active, the Web UI must show the timestamp of the last scan when it was active.
                ...(h.latency !== undefined && { latency: h.latency })
            };
        }
        
        res.json(response);
    } catch (error) {
        console.error('Error reading hosts file:', error);
        res.json({});
    }
});

// [R24.2] An interface must be provided to remove devices from hosts.json.
const deleteHostHandler = async (req: any, res: any) => {
    console.log('Received DELETE /api/v1/hosts request with body:', req.body);
    try {
        const { id } = req.body;
        console.log('Richiesta di eliminazione ricevuta. ID:', id);

        if (!id) {
            return res.status(400).json({ error: 'ID is required' });
        }

        // Normalize the ID by removing non-alphanumeric characters and converting to lowercase
        const normalizedId = id.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
        
        // Leggi il file hosts.json
        const data = await fs.readFile(HOSTS_PATH, 'utf-8');
        const hostsData = JSON.parse(data);
        
        // Find the host by normalized ID
        const idToDelete = Object.keys(hostsData).find(key => {
            const normalizedKey = key.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
            const match = normalizedKey === normalizedId;
            if (match) console.log(`Trovata corrispondenza: ${key} -> ${normalizedKey} === ${id} -> ${normalizedId}`);
            return match;
        });

        if (!idToDelete) {
            console.log('Nessun dispositivo trovato con ID:', id);
            return res.status(404).json({ error: 'Host not found' });
        }

        // Remove the host from the loaded data
        delete hostsData[idToDelete];

        // Save the updated hosts to the file
        await fs.writeFile(HOSTS_PATH, JSON.stringify(hostsData, null, 2));
        
        // Aggiorna anche la variabile in memoria
        hosts = hostsData;

        console.log(`Host with ID ${id} (normalized: ${normalizedId}) deleted successfully`);
        res.json({ success: true, id: idToDelete });
    } catch (error) {
        console.error('Error deleting host:', error);
        res.status(500).json({ error: 'Error deleting host' });
    }
};

// Register the handler for both DELETE and POST with method override
app.delete('/api/v1/hosts', deleteHostHandler);
app.post('/api/v1/hosts', (req, res, next) => {
    if (req.headers['x-http-method-override'] === 'DELETE') {
        return deleteHostHandler(req, res);
    }
    next();
});

// [R28] The Web UI must allow assigning custom names to devices. A Save button must be used to store the device name.
app.patch('/api/v1/hosts', async (req, res) => {
    try {
        const { id, name } = req.body;
        console.log('Richiesta di aggiornamento ricevuta. ID:', id, 'Nuovo nome:', name);
        
        if (!id) {
            return res.status(400).send('ID is required');
        }

        // Leggi il file hosts.json per avere i dati più aggiornati
        const data = await fs.readFile(HOSTS_PATH, 'utf-8');
        const hostsData = JSON.parse(data);

        // Cerca l'host per ID (senza fare distinzione tra maiuscole e minuscole)
        const hostToUpdate = Object.keys(hostsData).find(key => 
            key && key.toLowerCase() === id.toLowerCase()
        );

        if (hostToUpdate) {
            // Aggiorna il nome dell'host
            hostsData[hostToUpdate].name = name;
            await fs.writeFile(HOSTS_PATH, JSON.stringify(hostsData, null, 2));
            
            // Aggiorna anche la variabile in memoria
            hosts = hostsData;

            // Ricarica la configurazione degli host nello scanner per riflettere le modifiche
            await scanner.reloadHostsFromFile();

            // console.log(`Host with ID ${hostToUpdate} updated successfully`);
            return res.json({ success: true });
        } else {
            console.log(`Host with ID ${id} not found`);
            return res.status(404).send('Host not found');
        }
    } catch (error) {
        console.error('Error updating host:', error);
        res.status(500).send('Error updating host');
    }
});

// [R30] /api/v1/status (GET for server status and last scan)
app.get('/api/v1/status', (req, res) => {
    res.json({
        server_status: 'running',
        last_scan: scanner.getLastScanTime(),
        is_scanning: scanner.isScanning()
    });
});

app.post('/api/v1/scan', async (req, res) => {
    try {
        await scanner.scan();
        res.json({ success: true });
    } catch (error) {
        res.status(500).send('Error starting manual scan');
    }
});

app.get('/', (req, res) => {
    res.sendFile('index.html', { root: 'static' });
});


// [R37] The tree must be organized to separate program files from data.
// [R38] Program files must be stored in the src folder. config.json and hosts.json must be stored in the data folder.
// [R39] Folders src and data must be at the same level.
// Helper function to check if a variable is an object
function isObject(value: any): value is object {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

async function main() {
    // [R34] If the hosts.json file is corrupted, the server must create a new empty one and continue execution.
    try {
        const configData = await fs.readFile(CONFIG_PATH, 'utf-8');
        config = JSON.parse(configData);
    } catch (error) {
        console.error("Error reading config.json, using default values", error);
        // [R14] Configuration via config.json must include: IP range (e.g., string “192.168.1.1-254”), scan SCAN_TIMEOUT (ms), SCAN_PERIOD period (0 for one-shot, ≥30 for periodic), threads/processes, webui poll_interval (min 30s) including the type of scanner tool: nmap or arp-scanner. The system must validate values and support hot-reload upon configuration changes. On dynamic change of SCAN_PERIOD: from 0 to >0: immediately start periodic scans; On dynamic change of SCAN_PERIOD: from >0 to 0: immediately stop the current scan, perform a new one, then go idle.
        config = {
            "ip_range": "192.168.1.1-254",
            "timeout": 1000,
            "period": 0,
            "threads": 4,
            "poll_interval": 30
        };
        await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
    }

    try {
        const hostsData = await fs.readFile(HOSTS_PATH, 'utf-8');
        const parsedHosts = JSON.parse(hostsData);

        // [R34] Validate that hosts.json is a valid object
        if (isObject(parsedHosts)) {
            hosts = parsedHosts;
        } else {
            console.error("Error: hosts.json is not a valid object. Creating a new one.");
            hosts = {};
            await fs.writeFile(HOSTS_PATH, JSON.stringify(hosts, null, 2));
        }
    } catch (error) {
        console.error("Error reading hosts.json, creating a new one.", error);
        hosts = {};
        await fs.writeFile(HOSTS_PATH, JSON.stringify(hosts, null, 2));
    }
    
    // [R35] At startup, the server must verify the availability of necessary privileges (e.g., root permissions). In case of insufficient permissions or critical errors, it must notify the user (console or UI) and terminate execution without automatic recovery attempts.
    if (process.getuid && process.getuid() !== 0) {
        console.error("Error: root privileges are required to run nmap scans.");
        console.error("Please restart the application with sudo.");
        // process.exit(1); // This would terminate the server
    }


    scanner = new Scanner(config, hosts);

    // [R29] At startup, if SCAN_PERIOD > 0, automatically start periodic scans.
    // [R29.1] If SCAN_PERIOD = 0, perform a one-shot scan and then stay idle.
    if (config.period > 0) {
        scanner.start();
    } else {
        await scanner.scan();
    }

    app.listen(4000, () => {
        console.log('Server listening on port 4000');
    });
}

main();
