// [R27] The server must be developed in typescript for both scanning and the Web UI.
// [R32] The server must be implemented only in two files: main.ts and scanner.ts, organized into internal modules for clarity and modularity.

import express from 'express';
import * as fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import * as path from 'path';
import { Scanner, Config } from './scanner.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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

function isValidIP(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
        const num = Number(part);
        return Number.isInteger(num) && num >= 0 && num <= 255;
    });
}

function isValidRange(ipRange: string): boolean {
    if (isValidIP(ipRange)) return true;
    const m = ipRange.match(/^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/);
    if (!m) return false;
    const [, , start, end] = m;
    const s = Number(start);
    const e = Number(end);
    if (!Number.isInteger(s) || !Number.isInteger(e)) return false;
    if (s < 0 || e < 0 || s > 254 || e > 255 || s > e) return false;
    return true;
}

function validateConfig(payload: any, current?: Config): Config {
    const cfg: Config = {
        ip_range: payload?.ip_range ?? current?.ip_range ?? '192.168.1.1-254',
        timeout: Number(payload?.timeout ?? current?.timeout ?? 1000),
        period: Number(payload?.period ?? current?.period ?? 0),
        threads: Number(payload?.threads ?? current?.threads ?? 4),
        poll_interval: Number(payload?.poll_interval ?? current?.poll_interval ?? 30),
        scanner_type: (payload?.scanner_type ?? current?.scanner_type ?? 'nmap') as Config['scanner_type']
    };

    if (!isValidRange(cfg.ip_range)) {
        throw new Error('ip_range must be a single IPv4 or range like 192.168.1.1-254');
    }
    if (!Number.isInteger(cfg.timeout) || cfg.timeout <= 0) {
        throw new Error('timeout must be a positive integer (ms)');
    }
    if (!(cfg.period === 0 || cfg.period >= 30)) {
        throw new Error('period must be 0 or >= 30 seconds');
    }
    if (!Number.isInteger(cfg.poll_interval) || cfg.poll_interval < 30) {
        throw new Error('poll_interval must be >= 30 seconds');
    }
    if (!Number.isInteger(cfg.threads) || cfg.threads <= 0) {
        throw new Error('threads must be > 0');
    }
    if (cfg.scanner_type !== 'nmap' && cfg.scanner_type !== 'arp-scan') {
        throw new Error('scanner_type must be nmap or arp-scan');
    }
    return cfg;
}

let config: any;
let hosts: any = {};
let scanner: Scanner;

// [R30] /api/v1/config (GET to read, PUT to update configuration)
app.get('/api/v1/config', (req, res) => {
    res.json(config);
});

app.put('/api/v1/config', async (req, res) => {
    try {
        const validated = validateConfig(req.body, config);
        config = validated;
        await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
        res.json(config);
        // [R14] support hot-reload upon configuration changes
        scanner.updateConfig(config);
    } catch (error: any) {
        console.error('Config validation error:', error);
        res.status(400).send(error?.message || 'Error saving configuration');
    }
});

// [R30] /api/v1/hosts (GET full list, PATCH for partial updates, DELETE to remove devices)
app.get('/api/v1/hosts', async (req, res) => {
    try {
        // [R2, R13] Leggi direttamente dal file e calcola status e latency
        const data = await fs.readFile(HOSTS_PATH, 'utf-8');
        const fileHosts = JSON.parse(data);
        
        const response: HostsMap = {};
        const now = Math.floor(Date.now() / 1000);
        const SCAN_PERIOD = config.period || 0;
        const SCAN_TIMEOUT = config.timeout || 1000;
        
        for (const [mac, host] of Object.entries(fileHosts)) {
            const h = host as Host;
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
                // [R13] latency è incluso se disponibile nel file
                ...(h.latency !== undefined && { latency: h.latency })
            };
        }
        
        res.json(response);
    } catch (error) {
        console.error('Error reading hosts file:', error);
        res.json({});
    }
});

// Handle DELETE host requests
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
        last_scan: scanner.getLastScanTime()
    });
});

app.get('/', (req, res) => {
    res.sendFile('index.html', { root: path.join(__dirname, '../static') });
});


async function main() {
    // [R34] If the hosts.json file is corrupted, the server must create a new empty one and continue execution.
    try {
        const configData = await fs.readFile(CONFIG_PATH, 'utf-8');
        config = validateConfig(JSON.parse(configData));
    } catch (error) {
        console.error("Error reading config.json, using default values", error);
        config = validateConfig({});
        await fs.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2));
    }

    try {
        const hostsData = await fs.readFile(HOSTS_PATH, 'utf-8');
        hosts = JSON.parse(hostsData);
    } catch (error) {
        console.error("Error reading hosts.json, creating a new one.", error);
        hosts = {};
        await fs.writeFile(HOSTS_PATH, JSON.stringify(hosts, null, 2));
    }
    
    // [R35] At startup, the server must verify the availability of necessary privileges
    if (process.getuid && process.getuid() !== 0) {
        console.error("Error: root privileges are required to run nmap scans.");
        console.error("Please restart the application with sudo.");
        process.exit(1); // This would terminate the server
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
