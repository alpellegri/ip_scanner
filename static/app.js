// [R28.1] Frontend JavaScript implementation
let config = null;
let hosts = {}; // [R25] Using an object/map instead of an array

// Function to validate an IP address
function isValidIP(ip) {
    if (typeof ip !== 'string') return false;
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    return parts.every(part => {
        const num = parseInt(part, 10);
        return !isNaN(num) && num >= 0 && num <= 255;
    });
}

// Save configuration
async function saveConfig() {
    const formData = {
        ip_range: document.getElementById('ipRange').value,
        timeout: parseInt(document.getElementById('timeout').value),
        period: parseInt(document.getElementById('period').value),
        threads: parseInt(document.getElementById('threads').value),
        poll_interval: parseInt(document.getElementById('pollInterval').value),
        scanner_type: document.getElementById('scannerType').value
    };

    try {
        console.log('Saving configuration:', formData);
        const response = await fetch('/api/v1/config', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });

        if (response.ok) {
            const savedConfig = await response.json();
            config = savedConfig;
            console.log('Configuration saved successfully:', savedConfig);
            // Reload configuration to ensure sync
            await loadConfig();
            showNotification('Configuration saved successfully', 'success');
        } else {
            const errorText = await response.text();
            console.error('Failed to save configuration:', errorText);
            showNotification('Failed to save configuration: ' + errorText, 'error');
        }
    } catch (error) {
        console.error('Error saving configuration:', error);
        showNotification('Error saving configuration: ' + error.message, 'error');
    }
}

// Initialize the application
async function init() {
    await loadConfig();
    await loadHosts();
    setupEventListeners();
    startPolling();
}

// [R24] Load hosts data
async function loadHosts() {
    try {
        console.log('Loading hosts data...');
        const response = await fetch('/api/v1/hosts');
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const responseData = await response.json();
        
        // Convert the response to an array of hosts
        let hostsArray = [];
        if (Array.isArray(responseData)) {
            hostsArray = responseData;
        } else if (responseData && typeof responseData === 'object') {
            // Convert object of hosts to array
            hostsArray = Object.entries(responseData).map(([key, host]) => ({
                ...host,
                // Ensure we have a mac_address field
                mac_address: host.mac_address || host.mac || key,
                // Ensure we have an id field
                id: host.id || key
            }));
        }
        
        console.log('Processing', hostsArray.length, 'hosts');
        
        // Convert array to object with MAC as key for easier lookups
        const newHosts = {};
        hostsArray.forEach(host => {
            // Use MAC address as the primary key, fallback to IP
            const mac = host.mac_address || host.mac || host.id;
            const key = mac && mac.length > 0 ? mac : (host.ip && host.ip[0] ? host.ip[0] : null);
            
            if (key) {
                newHosts[key] = { 
                    ...host,
                    mac_address: mac,
                    id: key,
                    ip: Array.isArray(host.ip) ? host.ip : (host.ip ? [host.ip] : []),
                    latency: host.latency || 0
                };
            }
        });
        
        hosts = newHosts;
        console.log('Hosts data loaded:', Object.keys(hosts).length, 'hosts found');
        updateHostsTable();
    } catch (error) {
        console.error('Error loading hosts:', error);
        showNotification(`Error loading hosts: ${error.message}`, 'error');
    }
}

// Load configuration
async function loadConfig() {
    try {
        const response = await fetch('/api/v1/config');
        config = await response.json();
        updateConfigForm();
    } catch (error) {
        console.error('Error loading configuration:', error);
    }
}

// Update configuration form with current values
function updateConfigForm() {
    if (!config) return;
    
    console.log('Updating form with config:', config);
    document.getElementById('ipRange').value = config.ip_range || '';
    document.getElementById('timeout').value = config.timeout || 1000;
    document.getElementById('period').value = config.period || 0;
    document.getElementById('threads').value = config.threads || 4;
    document.getElementById('pollInterval').value = config.poll_interval || 30;
    document.getElementById('scannerType').value = config.scanner_type || 'nmap';
}

// [R24, R26, R24.0] Update hosts table
function updateHostsTable() {
    console.log('Updating hosts table with', Object.keys(hosts).length, 'hosts');
    console.log('Hosts data:', JSON.stringify(hosts, null, 2));
    const tbody = document.getElementById('hostsTable');
    if (!tbody) {
        console.error('Hosts table element not found');
        return;
    }
    tbody.innerHTML = '';

    // Group hosts by MAC address (or IP if MAC not available)
    const hostsByMac = {};
    
    // Process all hosts
    Object.values(hosts).forEach(host => {
        if (!host) return;
        
        // Get the actual MAC address
        const rawMac = (host.mac_address || host.mac || '').toString().trim();
        if (!rawMac || rawMac.length === 0) return; // Skip if no MAC
        
        // Filter only valid IPs
        const validIps = Array.isArray(host.ip) ? 
            host.ip.filter(ip => {
                const ipPart = (ip || '').toString().split('/')[0];
                return isValidIP(ipPart);
            }) : [];
            
        if (validIps.length === 0) return; // Skip if no valid IPs
        
        // Use rawMac as key (with colons if present)
        if (!hostsByMac[rawMac]) {
            hostsByMac[rawMac] = {
                ...host,
                ip: [...validIps], // Create a copy of the array
                mac_address: rawMac, // Keep original MAC format
                id: rawMac,
                original_ips: [...validIps] // Keep a copy of original IPs
            };
        } else {
            // If MAC exists, only add new IPs
            validIps.forEach(ip => {
                if (!hostsByMac[rawMac].ip.includes(ip)) {
                    hostsByMac[rawMac].ip.push(ip);
                    hostsByMac[rawMac].original_ips.push(ip);
                }
            });
        }
    });

    // Separate online and offline hosts
    const onlineHosts = [];
    const offlineHosts = [];
    
    Object.values(hostsByMac).forEach(host => {
        if (host.status && host.status.toLowerCase() === 'online') {
            onlineHosts.push(host);
        } else {
            offlineHosts.push(host);
        }
    });

    // Sort online hosts by first IP address
    onlineHosts.sort((a, b) => {
        try {
            const ipA = (a.ip && a.ip[0] ? a.ip[0] : '0.0.0.0').split('.').map(num => parseInt(num, 10));
            const ipB = (b.ip && b.ip[0] ? b.ip[0] : '0.0.0.0').split('.').map(num => parseInt(num, 10));
            for (let i = 0; i < 4; i++) {
                if (ipA[i] !== ipB[i]) {
                    return ipA[i] - ipB[i];
                }
            }
            return 0;
        } catch (e) {
            console.error('Error sorting IPs:', e);
            return 0;
        }
    });

    // Sort offline hosts by last seen (descending)
    offlineHosts.sort((a, b) => (b.last_seen || 0) - (a.last_seen || 0));

    // Combine the sorted lists
    const sortedHosts = [...onlineHosts, ...offlineHosts];
    const placeholderText = "Enter device name";

    // Generate table rows
    sortedHosts.forEach(host => {
        console.log('Processing host:', host);
        const d = new Date(host.last_seen * 1000);
        const date = d.toLocaleDateString();
        const time = d.toLocaleTimeString();
        const lastSeenHtml = `<div>${date}</div><div>${time}</div>`;
        
        // Format latency in seconds with 3 decimal places
        const latencyHtml = (host.latency !== undefined && host.latency !== null && host.latency >= 0) ? 
            `${(Number(host.latency) / 1000).toFixed(3)} s` : 'N/A';
        
        // Prepare IPs to display
        let displayIps = host.ip && host.ip.length > 0 ? 
            host.ip.filter(ip => ip && ip.trim() !== '').join('<br>') : 'N/A';
            
        // [R25] Format MAC address
        let formattedMac = '';
        const macToFormat = (host.mac_address || host.mac || '').toString().trim();
        
        // Handle only physical MAC addresses
        try {
            const cleanMac = macToFormat.replace(/[^0-9A-Fa-f]/g, '').toUpperCase();
            if (cleanMac.length === 12) {
                // Format as XX:XX:XX:XX:XX:XX
                formattedMac = cleanMac.match(/.{1,2}/g).join(':');
            } else {
                console.warn(`[R25] Invalid MAC address for host ${host.ip && host.ip[0]}: ${macToFormat}`);
                return; // Skip hosts without valid physical MAC
            }
        } catch (e) {
            console.error('[R25] Error formatting MAC:', e, 'Value:', macToFormat);
            return; // Skip this host due to MAC address processing error
        }

        const tr = document.createElement('tr');
        
        // Create safe ID for input element (remove special characters)
        const safeId = formattedMac.replace(/[^0-9A-Fa-f]/g, '');
        
        // Create DOM elements instead of using innerHTML to avoid issues with special characters
        tr.innerHTML = `
            <td class="status-cell"><span class="status-indicator ${host.status ? host.status.toLowerCase() : 'offline'}" title="${host.status || 'offline'}"></span></td>
            <td class="ip-cell">
                <div>${displayIps}</div>
            </td>
            <td class="device-cell">
                <div class="mac-display">${formattedMac}</div>
                <div class="device-main-row">
                    <input type="text" id="name-${safeId}" value="${host.name || host.hostname || ''}" placeholder="${placeholderText}" class="device-name-input">
                    <button class="icon-btn save-btn" data-id="${host.mac_address}" title="Save device name">💾</button>
                    <button class="icon-btn delete-btn" data-id="${host.mac_address}" title="Remove device">🗑️</button>
                </div>
                <div class="manufacturer-cell">${host.manufacturer || 'N/A'}</div>
            </td>
            <td class="${host.status && host.status.toLowerCase() === 'online' ? 'latency-cell' : 'timestamp-cell'}">
                ${host.status && host.status.toLowerCase() === 'online' ? latencyHtml : lastSeenHtml}
            </td>
        `;
        
        // Add event listeners to buttons
        const saveBtn = tr.querySelector('.save-btn');
        const deleteBtn = tr.querySelector('.delete-btn');
        
        if (saveBtn) {
            saveBtn.addEventListener('click', () => {
                const id = saveBtn.getAttribute('data-id');
                saveHostName(id);
            });
        }
        
        if (deleteBtn) {
            deleteBtn.addEventListener('click', () => {
                const id = deleteBtn.getAttribute('data-id');
                deleteHost(id);
            });
        }
        
        tbody.appendChild(tr);
        console.log(`Added row for host: ${host.ip ? host.ip.join(', ') : 'N/A'} (ID: ${host.id})`);
    });
}

// [R24.2] Delete host - Unified function
async function deleteHost(id) {
if (!id) {
    console.error('Unable to delete: Invalid ID');
    alert('Unable to delete device: Missing or invalid ID');
    return;
}

// Normalize MAC address format (remove any non-alphanumeric characters and convert to lowercase)
const normalizedId = id.replace(/[^0-9A-Fa-f]/g, '').toLowerCase();
    
if (!/^([0-9a-f]{2}){6}$/.test(normalizedId)) {
    console.error('Invalid MAC address format:', id);
    alert('Unable to delete device: Invalid MAC address format');
    return;
}

try {
    console.log('Sending delete request for MAC:', normalizedId);
        
    const response = await fetch('/api/v1/hosts', {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ id: normalizedId })
    });
    
    console.log('Response received:', response.status, response.statusText);
    
    if (response.ok) {
            console.log('Device deleted successfully');
            // Force a complete refresh of the hosts list from the server
            await loadHosts();
            
            // Close any open modals
            const modal = document.getElementById('editModal');
            if (modal) {
                modal.style.display = 'none';
            }
        } else {
            const errorData = await response.json().catch(() => ({}));
            const errorMessage = errorData.message || response.statusText || `Errore ${response.status}`;
            console.error('Error in server response:', response.status, errorMessage);
            throw new Error(errorMessage);
        }
    } catch (error) {
        console.error('Error during deletion:', error);
        alert(`An error occurred while deleting the device: ${error.message || error}`);
    }
}

// Function to save a custom host name
async function saveHostName(id) {
    console.log('Starting save - ID:', id);
    
    if (!id) {
        console.error('Host not found for ID:', id);
        return;
    }
    
    // Create safe ID for finding the input (remove special characters for MAC)
    const safeId = id.replace(/[^0-9A-Fa-f]/g, '');
    const inputId = `name-${safeId}`;
    const input = document.getElementById(inputId);
    
    if (!input) {
        console.error('Input not found with ID:', inputId);
        return;
    }
    
    const newName = input.value.trim();
    
    try {
        console.log('Sending update request for MAC:', id, 'New name:', newName);
        const response = await fetch('/api/v1/hosts', {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                id: id,
                name: newName
            })
        });
        
        console.log('Response received:', response.status, response.statusText);
        
        if (response.ok) {
            console.log('Device name updated successfully');
            await loadHosts();
        } else {
            const errorText = await response.text();
            console.error('Error saving name:', response.status, errorText);
        }
    } catch (error) {
        console.error('Error during name save:', error);
    }
}


// Setup event listeners
function setupEventListeners() {
    document.getElementById('configForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        await saveConfig();
    });

    const configHeader = document.getElementById('configHeader');
    const configContent = document.getElementById('configContent');
    const configToggleIcon = document.getElementById('configToggleIcon');

    configContent.classList.add('collapsed');
    configToggleIcon.style.transform = 'rotate(0deg)';

    configHeader.addEventListener('click', () => {
        configContent.classList.toggle('collapsed');
        configToggleIcon.style.transform = configContent.classList.contains('collapsed') ? 'rotate(0deg)' : 'rotate(90deg)';
    });
}

// [R24] Start polling for updates
function startPolling() {
    setInterval(async () => {
        await loadHosts();
    }, (config?.poll_interval || 30) * 1000);
}

// Initialize the application when the page loads
document.addEventListener('DOMContentLoaded', init);