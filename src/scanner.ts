// [R27] The server must be developed in typescript for both scanning and the Web UI.

// [R32] The server must be implemented only in two files: main.ts and scanner.ts, organized into internal modules for clarity and modularity.

import { exec } from 'child_process';
import * as fs from 'fs/promises';
import * as path from 'path';

// [R38] config.json and hosts.json must be stored in the data folder.
const HOSTS_PATH = './data/hosts.json';

// [R25] Interface representing a host device in the network
export interface Host {
    ip: string[];           // Array of IP addresses associated with the MAC
    hostname?: string;      // Device hostname if available
    mac: string;           // MAC address if available (format: XX:XX:XX:XX:XX:XX)
    name?: string;         // User-assigned name (takes precedence over hostname)
    status?: 'online' | 'offline';  // Current device status
    lastSeen: number;      // Timestamp of last successful scan
    manufacturer?: string; // Device manufacturer if available
    latency: number | null;  // Network latency in milliseconds
}

// Scanner type definition
export type ScannerType = 'nmap' | 'arp-scan';

// Base scanner interface
interface BaseScanner {
    scan(ipRange: string, timeout: number, threads: number): Promise<Host[]>;
}

// Nmap scanner implementation
class NmapScanner implements BaseScanner {
    async scan(ipRange: string, timeout: number, threads: number): Promise<Host[]> {
        const command = `nmap -sP -PR -n --send-eth \
            -T${threads} \
            --host-timeout ${timeout * 2}ms \
            --min-parallelism 50 \
            --max-retries 5 \
            --min-rate 50 \
            --max-rtt-timeout 1000ms \
            --initial-rtt-timeout 500ms \
            --min-rtt-timeout 100ms \
            ${ipRange}`;
        return this.executeCommand(command);
    }

    private async executeCommand(command: string): Promise<Host[]> {
        try {
            const { stdout, stderr } = await new Promise<{stdout: string, stderr: string}>((resolve, reject) => {
                exec(command, (error, stdout, stderr) => {
                    if (error && error.code !== 1) { // nmap returns 1 when no hosts are up
                        console.error(`nmap error: ${error.message}`);
                        resolve({ stdout: '', stderr });
                    } else {
                        resolve({ stdout, stderr });
                    }
                });
            });

            if (stderr) {
                console.error(`nmap stderr: ${stderr}`);
            }

            const hosts: Host[] = [];
            const lines = stdout.split('\n');
            let currentHost: Host | null = null;

            for (const line of lines) {
                const hostMatch = line.match(/Nmap scan report for (.+)/);
                const macMatch = line.match(/MAC Address: ((?:[0-9A-F]{2}:){5}[0-9A-F]{2}) \(([^)]+)\)/i);
                const latencyMatch = line.match(/Host is up \((.+)s latency\)/);

                if (hostMatch) {
                    if (currentHost) {
                        hosts.push(currentHost);
                    }

                    const hostData = hostMatch[1];
                    const ipMatch = hostData.match(/\(([0-9.]+)\)/);
                    const ip = ipMatch ? ipMatch[1] : hostData;
                    const hostname = ipMatch ? hostData.split(' ')[0] : '';

                    currentHost = {
                        ip: [ip],
                        mac: '',
                        hostname,
                        latency: null,
                        lastSeen: Date.now()
                    };
                } else if (macMatch && currentHost) {
                    currentHost.mac = macMatch[1].toUpperCase();
                    currentHost.manufacturer = macMatch[2];
                } else if (latencyMatch && currentHost) {
                    // nmap reports latency in seconds, convert to milliseconds to be consistent
                    currentHost.latency = parseFloat(latencyMatch[1]) * 1000;
                }
            }

            if (currentHost) {
                hosts.push(currentHost);
            }

            return hosts;
        } catch (error) {
            console.error('Error executing nmap command:', error);
            return [];
        }
    }
}

// Arp scanner implementation
class ArpScanner implements BaseScanner {
    private convertIPRange(ipRange: string): string | null {
        // Handle CIDR notation (e.g., 192.168.1.0/24)
        if (ipRange.includes('/')) {
            return ipRange;
        }

        // Handle range notation (e.g., 192.168.1.1-253)
        const match = ipRange.match(/^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/);
        if (match) {
            const [, prefix, start, end] = match;
            const startNum = parseInt(start);
            const endNum = parseInt(end);
            
            if (startNum < 0 || startNum > 255 || endNum < 0 || endNum > 255 || startNum > endNum) {
                return null;
            }

            if (startNum === 0 && endNum === 255) {
                return `${prefix}0/24`;
            }

            // For smaller ranges, list individual IPs
            return Array.from(
                { length: endNum - startNum + 1 },
                (_, i) => `${prefix}${startNum + i}`
            ).join(' ');
        }

        // Single IP address
        if (ipRange.match(/^\d+\.\d+\.\d+\.\d+$/)) {
            return ipRange;
        }

        return null;
    }

    async scan(ipRange: string, timeout: number, threads: number): Promise<Host[]> {
        // Convert IP range format from nmap style (192.168.1.1-253) to CIDR notation for arp-scan
        const convertedRange = this.convertIPRange(ipRange);
        if (!convertedRange) {
            console.error('Invalid IP range format:', ipRange);
            return [];
        }

        // First do arp-scan to get MAC addresses
        const scanCommand = `arp-scan --timeout=${timeout} --retry=3 --backoff=2 ${convertedRange}`;
        const hosts = await this.executeScan(scanCommand);
        
        // Then use nping for latency measurement
        const promises = hosts.map(async (host) => {
            if (host.ip.length > 0) {
                host.latency = await this.measureLatency(host.ip[0]);
            }
            return host;
        });

        return Promise.all(promises);
    }

    private async executeScan(command: string): Promise<Host[]> {
        try {
            const { stdout, stderr } = await new Promise<{stdout: string, stderr: string}>((resolve, reject) => {
                exec(command, (error, stdout, stderr) => {
                    if (error && error.code !== 1) { // arp-scan returns 1 when no hosts are up
                        console.error(`arp-scan error: ${error.message}`);
                        resolve({ stdout: '', stderr });
                    } else {
                        resolve({ stdout, stderr });
                    }
                });
            });

            if (stderr) {
                console.error(`arp-scan stderr: ${stderr}`);
            }

            const hosts: Host[] = [];
            const lines = stdout.split('\n');

            for (const line of lines) {
                // Ignore header lines and empty lines
                if (line.startsWith('\t') || line.includes('Interface:') || line.includes('Starting') || !line.trim()) {
                    continue;
                }

                // Parse arp-scan output format: IP MAC Manufacturer
                const match = line.match(/^([0-9.]+)\s+([0-9a-fA-F:]{17})\s+(.*)$/);
                if (match) {
                    const [, ip, mac, manufacturer] = match;
                    hosts.push({
                        ip: [ip],
                        mac: mac.toUpperCase(),
                        manufacturer: manufacturer.trim() || 'Unknown',
                        lastSeen: Date.now(),
                        latency: null,
                        status: 'online'
                    });
                }
            }

            return hosts;
        } catch (error) {
            console.error('Error executing arp-scan command:', error);
            return [];
        }
    }

    private async measureLatency(ip: string): Promise<number | null> {
        const command = `nping --tcp-connect -c 3 --delay 0 ${ip}`;
        try {
            const { stdout } = await new Promise<{stdout: string, stderr: string}>((resolve, reject) => {
                exec(command, (error, stdout, stderr) => {
                    if (error) {
                        console.error(`nping error: ${error.message}`);
                        resolve({ stdout: '', stderr });
                    } else {
                        resolve({ stdout, stderr });
                    }
                });
            });

            const match = stdout.match(/Avg rtt:\s+([0-9.]+)/);
            return match ? parseFloat(match[1]) : null;

        } catch (error) {
            console.error('Error executing nping command:', error);
            return null;
        }
    }
}

// [R14] Configuration interface
export interface Config {
    ip_range: string;      // Single IP or range (e.g., 192.168.1.1-254)
    timeout: number;       // SCAN_TIMEOUT in milliseconds
    period: number;        // SCAN_PERIOD in seconds (0 for one-shot, ≥30 for periodic)
    threads: number;       // Number of threads/processes for nmap
    poll_interval: number; // WebUI poll interval in seconds (min 30)
    scanner_type: ScannerType; // Type of scanner to use: nmap or arp-scan
}

export class Scanner {
    private config: Config;
    private hosts: { [mac: string]: Host };
    private timer: NodeJS.Timeout | null = null;
    private lastScanTime: number | null = null;
    private scanning: boolean = false;
    private scanner: BaseScanner;

    constructor(config: Config, hosts: any) {
        this.config = config;
        this.hosts = {};
        this.scanner = config.scanner_type === 'nmap' ? new NmapScanner() : new ArpScanner();
        
        // Initialize hosts from existing data
        if (Array.isArray(hosts)) {
            // Convert array to object with MAC keys
            hosts.forEach(host => {
                const mac = host.mac;
                if (mac && this.isValidMAC(mac)) {
                    const normalizedMac = this.normalizeMacAddress(mac);
                    this.hosts[normalizedMac] = {
                        ip: Array.isArray(host.ip) ? host.ip : [],
                        hostname: host.hostname || '',
                        mac: normalizedMac,
                        name: host.name || '',
                        status: host.status || 'offline',
                        lastSeen: host.lastSeen || 0,
                        manufacturer: host.manufacturer || 'Unknown',
                        latency: host.latency || null
                    };
                }
            });
        } else if (hosts && typeof hosts === 'object') {
            // Process object format with MAC keys
            Object.entries(hosts).forEach(([key, host]: [string, any]) => {
                if (this.isValidMAC(key)) {
                    const normalizedMac = this.normalizeMacAddress(key);
                    this.hosts[normalizedMac] = {
                        ip: Array.isArray(host.ip) ? host.ip : [],
                        hostname: host.hostname || '',
                        mac: normalizedMac,
                        name: host.name || '',
                        status: host.status || 'offline',
                        lastSeen: host.lastSeen || 0,
                        manufacturer: host.manufacturer || 'Unknown',
                        latency: host.latency || null
                    };
                }
            });
        }
    }

    public async reloadHostsFromFile() {
        try {
            const hostsData = await fs.readFile(HOSTS_PATH, 'utf-8');
            const hostsFromFile = JSON.parse(hostsData);
            
            this.hosts = {}; // Clear existing hosts
            Object.entries(hostsFromFile).forEach(([key, host]: [string, any]) => {
                if (this.isValidMAC(key)) {
                    const normalizedMac = this.normalizeMacAddress(key);
                    this.hosts[normalizedMac] = {
                        ip: Array.isArray(host.ip) ? host.ip : [],
                        hostname: host.hostname || '',
                        mac: normalizedMac,
                        name: host.name || '',
                        status: host.status || 'offline',
                        lastSeen: host.lastSeen || 0,
                        manufacturer: host.manufacturer || 'Unknown',
                        latency: host.latency || null
                    };
                }
            });
            console.log('Scanner hosts reloaded from file.');
        } catch (error) {
            if (error.code !== 'ENOENT') {
                console.error("Error reloading hosts.json for scanner:", error);
            }
        }
    }

    // [R14] Configuration update with dynamic behavior
    public updateConfig(newConfig: Config) {
        const oldPeriod = this.config.period;
        this.config = newConfig;

        // Handle dynamic SCAN_PERIOD changes
        if (oldPeriod > 0 && newConfig.period === 0) {
            // From periodic to one-shot
            this.stop();
            this.scan(); // Immediate one-shot scan
        } else if (oldPeriod === 0 && newConfig.period > 0) {
            // From one-shot to periodic
            this.start();
        } else if (oldPeriod !== newConfig.period && newConfig.period > 0) {
            // Period changed but still periodic
            this.restart();
        }
    }

    // [R29] Start periodic scanning
    public start() {
        this.stop(); // Ensure no existing timer
        
        if (this.config.period > 0) {
            console.log(`Starting periodic scan every ${this.config.period} seconds`);
            this.timer = setInterval(() => this.scan(), this.config.period * 1000);
            this.scan(); // Run initial scan immediately
        } else {
            // [R29.1] One-shot scan
            console.log('Running one-shot scan');
            this.scan();
        }
    }

    public stop() {
        if (this.timer) {
            console.log('Stopping periodic scan');
            clearInterval(this.timer);
            this.timer = null;
        }
    }

    private restart() {
        this.stop();
        this.start();
    }

    public getLastScanTime(): number | null {
        return this.lastScanTime;
    }

    public isScanning(): boolean {
        return this.scanning;
    }

    // Validate MAC address format (both physical and virtual)
    private isValidMAC(mac: string | null | undefined): boolean {
        if (!mac) return false;
        
        // Only accept physical MAC addresses (XX:XX:XX:XX:XX:XX)
        const cleanMac = mac.replace(/[^0-9A-Fa-f]/g, '');
        return cleanMac.length === 12;
    }

    // [R25] Normalize MAC address to XX:XX:XX:XX:XX:XX format - only physical MACs
    private normalizeMacAddress(mac: string | null | undefined): string {
        if (!mac) return '';
        
        // Only handle physical MAC addresses
        const normalized = mac.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
        
        // Return empty string if not a valid MAC
        if (normalized.length !== 12) {
            return '';
        }
        
        // Format valid MAC with colons
        return normalized.replace(/([0-9A-F]{2})(?=[0-9A-F]{2})/g, '$1:');
        
        return '';
    }

    // Removed generateVirtualMAC as we only support physical MAC addresses

    // Validate IP address format
    private isValidIP(ip: string): boolean {
        if (!ip) return false;
        const parts = ip.split('.');
        if (parts.length !== 4) return false;
        
        return parts.every(part => {
            const num = parseInt(part, 10);
            return !isNaN(num) && num >= 0 && num <= 255 && num.toString() === part;
        });
    }

    // [R1.0] Scan IP range with selected scanner
    public async scan(): Promise<void> {
        if (this.scanning) {
            console.log('Scan already in progress, skipping');
            return;
        }

        this.scanning = true;
        this.lastScanTime = Date.now();
        console.log(`Scanning IP range: ${this.config.ip_range} using ${this.config.scanner_type} scanner`);

        try {
            const onlineHosts = await this.scanner.scan(
                this.config.ip_range,
                this.config.timeout,
                this.config.threads
            );
            await this.updateHosts(onlineHosts);
            // Ensure hosts.json is saved after updating hosts
            await this.saveToFile();
        } catch (error) {
            console.error('Scan error:', error);
        } finally {
            this.scanning = false;
        }
    }

    // [R25] Updates the hosts list with the results of the latest scan
    private async updateHosts(onlineHosts: Host[]): Promise<void> {
        const now = Math.floor(Date.now() / 1000);
        const onlineKeys = new Set<string>();

        console.log(`[R25] Updating hosts with ${onlineHosts.length} online hosts`);

        // First pass: update existing hosts and normalize MAC addresses
        for (const [key, existingHost] of Object.entries(this.hosts)) {
            if (this.isValidMAC(existingHost.mac)) {
                const normalizedMac = this.normalizeMacAddress(existingHost.mac);
                if (!this.isValidMAC(normalizedMac)) {
                    console.log(`[R25] Invalid normalized MAC ${normalizedMac} from ${existingHost.mac} - removing host`);
                    delete this.hosts[key];
                } else if (key !== normalizedMac) {
                    this.hosts[normalizedMac] = { ...existingHost };
                    delete this.hosts[key];
                    console.log(`[R25] Normalized MAC key from ${key} to ${normalizedMac}`);
                }
            } else {
                // Skip hosts without valid MAC per R25
                if (existingHost.ip && existingHost.ip.length > 0) {
                    console.log(`[R25] Removing host without MAC: ${existingHost.ip[0]}`);
                    delete this.hosts[key];
                } else {
                    console.log(`[R25] Removing entry without valid MAC or IP: ${key}`);
                    delete this.hosts[key];
                }
            }
        }

        // Mark all hosts offline first
        for (const host of Object.values(this.hosts)) {
            host.status = 'offline';
        }

        // Second pass: update online hosts and add new ones
        for (const onlineHost of onlineHosts) {
            // Skip hosts without physical MAC per R25
            if (!onlineHost.mac || !this.isValidMAC(onlineHost.mac)) {
                const firstIP = Array.isArray(onlineHost.ip) ? onlineHost.ip[0] : onlineHost.ip;
                if (firstIP) {
                    console.log(`[R25] Skipping host without valid MAC: ${firstIP} (MAC: ${onlineHost.mac || 'none'})`);
                } else {
                    console.warn('[R25] Skipping host without valid IP:', onlineHost);
                }
                continue;
            }

            const normalizedMac = this.normalizeMacAddress(onlineHost.mac);
            if (!normalizedMac) {
                console.warn('[R25] Failed to normalize MAC:', onlineHost.mac);
                continue;
            }

            if (!this.isValidMAC(normalizedMac)) {
                console.warn('[R25] Invalid normalized MAC:', normalizedMac, 'from', onlineHost.mac);
                continue;
            }

            // Debugging log
            console.log(`[R25] Processing online host with MAC: ${normalizedMac}`);

            // Mark this host as online using MAC as key
            onlineKeys.add(normalizedMac);

            const existingHost = this.hosts[normalizedMac] || {};
            const isNewHost = !this.hosts[normalizedMac];

            // Update host information
            this.hosts[normalizedMac] = {
                ...existingHost,
                ip: (() => {
                    const existingIps = Array.isArray(existingHost.ip) ? existingHost.ip : [];
                    const newIps = Array.isArray(onlineHost.ip) 
                        ? onlineHost.ip.filter(ip => this.isValidIP(ip))
                        : [onlineHost.ip].filter(ip => this.isValidIP(ip));
                    return [...new Set([...existingIps, ...newIps])];
                })(),
                hostname: onlineHost.hostname || existingHost.hostname || '',
                mac: normalizedMac,
                name: existingHost.name || 
                    (onlineHost.hostname && !this.isValidIP(onlineHost.hostname) 
                        ? onlineHost.hostname 
                        : ''),
                status: 'online',  // Set status to online for found hosts
                lastSeen: now,
                manufacturer: onlineHost.manufacturer || existingHost.manufacturer || 'Unknown',
                latency: onlineHost.latency !== undefined ? onlineHost.latency : (existingHost.latency || null)
            };

            // [R5] Devices responding to the scanner tool must be displayed in standard output
            const { ip, mac, hostname, manufacturer, latency } = this.hosts[normalizedMac];
            console.log(`IP ${ip.join(', ')}: OK, MAC: ${mac}, hostname: ${hostname || 'N/A'}, manufacturer: ${manufacturer || 'N/A'}, latency: ${latency !== null ? latency.toFixed(2) : 'N/A'} ms`);
            
            if (isNewHost) {
                console.log(`[R25] New device discovered: ${this.hosts[normalizedMac].name || 'Unnamed'} (${normalizedMac})`);
            } else {
                console.log(`[R25] Updated existing host: ${this.hosts[normalizedMac].name || 'Unnamed'} (${normalizedMac})`);
            }
        }

        // Debug log of online keys
        console.log(`[R25] Online keys after scan:`, Array.from(onlineKeys));

        // Update offline status for hosts not seen in this scan
        const onlineKeysArray = Array.from(onlineKeys);
        console.log(`[R25] Found ${onlineKeysArray.length} online hosts:`, onlineKeysArray);
        
        for (const [mac, host] of Object.entries(this.hosts)) {
            const normalizedMac = this.normalizeMacAddress(mac);
            if (!normalizedMac) {
                console.log(`[R25] Removing host with invalid MAC: ${mac}`);
                delete this.hosts[mac];
                continue;
            }

            // [R25] A device becomes offline if it does not respond to the scanner tool
            if (!onlineKeys.has(normalizedMac)) {
                console.log(`[R25] Host ${host.name || normalizedMac} (${normalizedMac}) did not respond - marking offline`);
                this.hosts[normalizedMac] = {
                    ...host,
                    status: 'offline'  // Status is set directly, no timestamp check
                };
                
                // If this was a renormalization, clean up old key
                if (mac !== normalizedMac) {
                    delete this.hosts[mac];
                }
            } else {
                // [R25] A device is updated as online only if it responds to the scanner tool
                console.log(`[R25] Host ${host.name || normalizedMac} (${normalizedMac}) responded to scan - marking online`);
                if (mac !== normalizedMac) {
                    this.hosts[normalizedMac] = {
                        ...host,
                        mac: normalizedMac,
                        status: 'online',  // Status is set directly based on scanner response
                        lastSeen: now
                    };
                    delete this.hosts[mac];
                } else {
                    host.status = 'online';  // Status is set directly based on scanner response
                    host.lastSeen = now;
                }
            }
        }

        // Save updated hosts to file
    }

    // Make saveToFile public
    public async saveToFile() {
        const dataToSave: { [key: string]: any } = {};
        const now = Math.floor(Date.now() / 1000);
        
        console.log(`[R25] Saving ${Object.keys(this.hosts).length} hosts to file`);
        
        // Transform data to ensure correct format
        for (const [mac, host] of Object.entries(this.hosts)) {
            // Only save hosts with valid physical MAC addresses
            if (!this.isValidMAC(mac)) {
                console.warn(`[R25] Skipping host with invalid MAC key: ${mac}`);
                continue;
            }
            
            // Filter out invalid IPs
            const validIps = Array.isArray(host.ip) 
                ? host.ip.filter(ip => this.isValidIP(ip))
                : [];
            
            if (validIps.length === 0) {
                console.warn(`[R25] Skipping host ${mac} without valid IPs`);
                continue;
            }
            
            // [R25] Save only required fields in the correct format
            dataToSave[mac] = {
                ip: validIps,
                hostname: host.hostname || '',
                manufacturer: host.manufacturer || (mac.startsWith('IP-') ? 'Unknown (No MAC)' : 'Unknown'),
                name: host.name || '',
                lastSeen: host.lastSeen || Math.floor(Date.now() / 1000),
                latency: host.latency !== undefined ? host.latency : null,
                status: host.status || 'offline'
            };
        }

        try {
            await fs.mkdir(path.dirname(HOSTS_PATH), { recursive: true });
            await fs.writeFile(HOSTS_PATH, JSON.stringify(dataToSave, null, 2));
            console.log(`[R25] Updated hosts.json with ${Object.keys(dataToSave).length} devices`);
        } catch (error) {
            // [R34] Handle file system errors gracefully
            console.error('[R25] Error saving hosts file:', error);
            // Don't throw the error to maintain scanning operation
            console.error('[R34] Continuing operation despite file save error');
        }
    }
}