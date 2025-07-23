import os
import subprocess
import secrets
import toml
import psutil
import glob
import json
import time
import re
from datetime import datetime, timezone
import iptables_manager

# --- Constants ---
RATHOLE_EXECUTABLE = "rathole"
APP_DIR = "/opt/my-tunnel-manager"
CONFIG_DIR = os.path.join(APP_DIR, 'instance', 'rathole_configs')
METADATA_FILE = os.path.join(CONFIG_DIR, 'metadata.json')
PANEL_LOG_FILE = os.path.join(APP_DIR, 'instance', 'panel.log')

# --- Logging ---
def log_message(message):
    try:
        os.makedirs(os.path.dirname(PANEL_LOG_FILE), exist_ok=True)
        if not os.path.exists(PANEL_LOG_FILE):
            with open(PANEL_LOG_FILE, "w") as f:
                pass
            os.chmod(PANEL_LOG_FILE, 0o666)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open(PANEL_LOG_FILE, "a") as f:
            f.write(f"[{timestamp} UTC] {message}")
    except Exception as e:
        print(f"!!! FAILED TO WRITE TO LOG FILE {PANEL_LOG_FILE}: {e} !!!")
        print(f"Original log message was: {message}")

# --- In-Memory State ---
service_configurations_cache = {}
log_message("--- rathole_manager.py module loaded, cache initialized ---")

# --- Core Helper & Status Functions ---
def ensure_config_dir():
    os.makedirs(CONFIG_DIR, exist_ok=True)

def _get_process_by_key(process_key):
    instance_type, instance_name = process_key.split('_', 1)
    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.name().lower() == 'rathole' and proc.cmdline() and config_path in proc.cmdline():
                return proc
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    return None

# More specific keywords based on rathole log format
# Success is determined by a forwarder being established for a service.
SUCCESS_KEYWORDS = ["forwarder for service established", "control channel connected"]
# Errors are more clear, but 'timed out' and 'connection refused' are very specific.
ERROR_KEYWORDS = ["error", "failed", "timed out", "connection refused", "retrying"]

def get_process_status(instance_type, instance_name):
    """
    Checks process status and performs a real-time health check by reading recent log entries.
    Returns: 'stopped', 'running' (process up, but connection failed/unverified), 'active' (connection verified)
    """
    proc = _get_process_by_key(f"{instance_type}_{instance_name}")
    if not proc:
        return 'stopped'

    log_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.log")
    if not os.path.exists(log_path):
        return 'running'

    try:
        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
            recent_lines = lines[-20:]
            log_pattern = re.compile(r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)')
            latest_success_time, latest_error_time = None, None

            for line in recent_lines:
                match = log_pattern.match(line)
                if not match: continue

                try:
                    log_time = datetime.fromisoformat(match.group(1).replace('Z', '+00:00'))
                except ValueError:
                    continue # Skip malformed timestamps

                if "established" in line or "Connected to server" in line:
                    if latest_success_time is None or log_time > latest_success_time:
                        latest_success_time = log_time
                elif "retrying" in line.lower() or "error" in line.lower() or "failed" in line.lower():
                    if latest_error_time is None or log_time > latest_error_time:
                        latest_error_time = log_time

            if latest_success_time:
                if latest_error_time and latest_error_time > latest_success_time:
                    return 'running'
                return 'active'
    except Exception as e:
        log_message(f"Health check for '{instance_name}' failed during log parsing: {e}")

    return 'running'

# --- Metadata Management ---
def _load_metadata():
    ensure_config_dir()
    if not os.path.exists(METADATA_FILE): return {}
    try:
        with open(METADATA_FILE, 'r') as f: return json.load(f)
    except (json.JSONDecodeError, IOError): return {}

def _save_metadata(data):
    ensure_config_dir()
    with open(METADATA_FILE, 'w') as f: json.dump(data, f, indent=2)

# --- Config Loading and Caching ---
def load_all_from_disk():
    """Loads all service configurations from disk into the in-memory cache."""
    global service_configurations_cache
    log_message("CACHE-INVALIDATION: Reloading all configurations from disk.")
    ensure_config_dir()
    unified_configs = {}

    for instance_type in ['server', 'client']:
        instance_files = glob.glob(os.path.join(CONFIG_DIR, f'{instance_type}_*.toml'))
        for f_path in instance_files:
            try:
                config = toml.load(f_path)
                instance_name = os.path.basename(f_path)[len(instance_type)+1:-len('.toml')]
                details = config.get(instance_type, {})

                if instance_type == 'server':
                    for service_name, svc_details in details.get('services', {}).items():
                        unified_configs[service_name] = {
                            'name': service_name, 'service_type': 'server_service',
                            'token': svc_details.get('token', details.get('default_token')),
                            'server_bind_addr': svc_details.get('bind_addr'),
                            'parent_instance': instance_name,
                            'protocol': svc_details.get('type', 'tcp')
                        }
                elif instance_type == 'client':
                    for service_name, svc_details in details.get('services', {}).items():
                        unified_configs[service_name] = {
                            'name': service_name, 'service_type': 'client_service',
                            'token': svc_details.get('token', details.get('default_token')),
                            'local_addr': svc_details.get('local_addr'),
                            'remote_addr': details.get('remote_addr'),
                            'parent_instance': instance_name,
                            'protocol': svc_details.get('type', 'tcp')
                        }
            except Exception as e: log_message(f"Error loading config {f_path}: {e}")
    service_configurations_cache = unified_configs
    log_message(f"CACHE-RELOADED: Found {len(service_configurations_cache)} total services.")

# --- Data Getters (UI Facing) ---
def get_all_services():
    if not service_configurations_cache:
        load_all_from_disk()
    return service_configurations_cache

import database

def get_instance(instance_type, instance_name):
    """Gets all configuration and status details for a single instance."""
    try:
        config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
        if not os.path.exists(config_path):
            return None

        config = toml.load(config_path)
        details = config.get(instance_type, {})
        metadata = _load_metadata().get(f"{instance_type}_{instance_name}", {})

        instance_traffic = {'sent': 0, 'recv': 0}
        services = details.get('services', {})
        for service_name in services.keys():
            service_stats_db = database.get_traffic_data(service_name) or {'sent_bytes': 0, 'recv_bytes': 0}

            # Prepare the dictionary for the frontend
            service_stats_frontend = {
                'sent': service_stats_db.get('sent_bytes', 0),
                'recv': service_stats_db.get('recv_bytes', 0)
            }

            instance_traffic['sent'] += service_stats_frontend['sent']
            instance_traffic['recv'] += service_stats_frontend['recv']
            services[service_name]['traffic'] = service_stats_frontend

        instance_data = {
            'name': instance_name,
            'status': get_process_status(instance_type, instance_name),
            'addr': details.get('bind_addr') or details.get('remote_addr'),
            'auto_restart': metadata.get('auto_restart', False),
            'service_count': len(services),
            'traffic': {'sent': instance_traffic['sent'], 'recv': instance_traffic['recv']},
            'services': services,
            'transport_protocol': details.get('transport', {}).get('type', 'tcp'),
            'public_key': metadata.get('public_key'),
            'default_token': details.get('default_token')
        }

        if instance_data['transport_protocol'] == 'tls':
            tls_config = details.get('transport', {}).get('tls', {})
            if instance_type == 'server':
                instance_data['tls_pkcs12'] = tls_config.get('pkcs12')
                instance_data['tls_pkcs12_password'] = tls_config.get('pkcs12_password')
                instance_data['tls_cert_content'] = _get_server_cert_content(instance_name)
            else: # Client
                trusted_root_path = tls_config.get('trusted_root')
                instance_data['tls_trusted_root'] = trusted_root_path
                instance_data['tls_trusted_root_content'] = _get_client_cert_content(trusted_root_path)

        return instance_data

    except Exception as e:
        log_message(f"Error getting instance details for {instance_type}_{instance_name}: {e}")
        return None

def _get_server_cert_content(instance_name):
    cert_path = os.path.join(CONFIG_DIR, f"server_{instance_name}.crt")
    if not os.path.exists(cert_path):
        return None
    try:
        with open(cert_path, 'r') as f:
            return f.read()
    except IOError as e:
        log_message(f"Failed to read cert for server_{instance_name}: {e}")
        return None

def _get_client_cert_content(cert_path):
    if not cert_path or not os.path.exists(cert_path):
        return None
    try:
        with open(cert_path, 'r') as f:
            return f.read()
    except IOError as e:
        log_message(f"Failed to read trusted root cert at {cert_path}: {e}")
        return None

def get_all_instances(instance_type):
    if not service_configurations_cache:
        load_all_from_disk()

    instances = {}
    metadata = _load_metadata()

    instance_names = set()
    for service in service_configurations_cache.values():
        if service['service_type'] == f"{instance_type}_service":
            instance_names.add(service['parent_instance'])

    # Also scan for empty instances
    instance_files = glob.glob(os.path.join(CONFIG_DIR, f'{instance_type}_*.toml'))
    for f_path in instance_files:
        instance_names.add(os.path.basename(f_path)[len(instance_type)+1:-len('.toml')])

    for instance_name in instance_names:
        try:
            config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
            config = toml.load(config_path)
            details = config.get(instance_type, {})
            instance_key = f"{instance_type}_{instance_name}"
            instance_meta = metadata.get(instance_key, {})

            instance_traffic = {'sent': 0, 'recv': 0}
            services = details.get('services', {})
            for service_name in services.keys():
                service_stats_db = database.get_traffic_data(service_name) or {'sent_bytes': 0, 'recv_bytes': 0}

                # Prepare the dictionary for the frontend
                service_stats_frontend = {
                    'sent': service_stats_db.get('sent_bytes', 0),
                    'recv': service_stats_db.get('recv_bytes', 0)
                }

                instance_traffic['sent'] += service_stats_frontend['sent']
                instance_traffic['recv'] += service_stats_frontend['recv']
                services[service_name]['traffic'] = service_stats_frontend

            instance_data = {
                'name': instance_name,
                'status': get_process_status(instance_type, instance_name),
                'addr': details.get('bind_addr') or details.get('remote_addr'),
                'auto_restart': instance_meta.get('auto_restart', False),
                'service_count': len(services),
                'traffic': {'sent': instance_traffic['sent'], 'recv': instance_traffic['recv']},
                'services': services,
                'transport_protocol': details.get('transport', {}).get('type', 'tcp'),
                'public_key': instance_meta.get('public_key'),
            }

            if instance_data['transport_protocol'] == 'tls':
                tls_config = details.get('transport', {}).get('tls', {})
                if instance_type == 'server':
                    instance_data['tls_pkcs12'] = tls_config.get('pkcs12')
                    instance_data['tls_pkcs12_password'] = tls_config.get('pkcs12_password')
                    instance_data['tls_cert_content'] = _get_server_cert_content(instance_name)
                else: # Client
                    trusted_root_path = tls_config.get('trusted_root')
                    instance_data['tls_trusted_root'] = trusted_root_path
                    instance_data['tls_trusted_root_content'] = _get_client_cert_content(trusted_root_path)

            instances[instance_name] = instance_data

        except Exception as e:
            log_message(f"Error parsing {instance_type} file {instance_name}.toml: {e}")
    return instances

# --- Process Management ---
def start_instance(instance_type, instance_name):
    if get_process_status(instance_type, instance_name) != 'stopped': return True
    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
    log_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.log")
    if not os.path.exists(config_path): return False

    try:
        with open(log_path, 'a') as log_file:
            process = subprocess.Popen([RATHOLE_EXECUTABLE, config_path], stdout=log_file, stderr=subprocess.STDOUT, text=True, env={**os.environ, "RUST_LOG": "info"})
        time.sleep(0.5)
        if process.poll() is not None:
            log_message(f"Error: Process for '{instance_name}' terminated immediately.")
            return False
        return True
    except Exception as e:
        log_message(f"CRITICAL ERROR in start_instance for '{instance_name}': {e}")
        return False

def stop_process(instance_type, instance_name):
    proc = _get_process_by_key(f"{instance_type}_{instance_name}")
    if not proc: return True

    try:
        proc.terminate()
        proc.wait(timeout=3)
    except psutil.TimeoutExpired:
        proc.kill()
    except (psutil.NoSuchProcess, Exception) as e:
        log_message(f"Error stopping process '{instance_name}': {e}")
        return False
    return True

# --- Config Management (UI Facing) ---
def _generate_noise_keys():
    private_key = subprocess.check_output("wg genkey", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"echo {private_key} | wg pubkey", shell=True).decode('utf-8').strip()
    return private_key, public_key

def _generate_tls_cert(instance_name, password):
    cert_path = os.path.join(CONFIG_DIR, f"{instance_name}.crt")
    key_path = os.path.join(CONFIG_DIR, f"{instance_name}.key")
    pfx_path = os.path.join(CONFIG_DIR, f"{instance_name}.pfx")

    # Generate certificate and key
    subprocess.check_output(f"openssl req -x509 -newkey rsa:4096 -keyout {key_path} -out {cert_path} -days 365 -nodes -subj '/CN=localhost'", shell=True)

    # Create PKCS#12 archive
    subprocess.check_output(f"openssl pkcs12 -export -out {pfx_path} -inkey {key_path} -in {cert_path} -passout pass:{password}", shell=True)

    # We keep the .crt and .key files for reference or renewal, so no cleanup needed here.
    return pfx_path

def _save_trusted_root_cert(instance_name, cert_content):
    if not cert_content: return None
    cert_path = os.path.join(CONFIG_DIR, f"client_{instance_name}_ca.crt")
    try:
        with open(cert_path, 'w') as f:
            f.write(cert_content)
        return cert_path
    except IOError as e:
        log_message(f"Failed to save trusted root cert for {instance_name}: {e}")
        return None

def add_instance(instance_type, instance_name, addr, default_token=None, auto_restart=False, transport_protocol='tcp', remote_public_key=None, tls_trusted_root_content=None, tls_pkcs12_password=None):
    if not all([instance_type, instance_name, addr]): return False
    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
    if os.path.exists(config_path): return False

    config_data = {'services': {}}
    if default_token: config_data['default_token'] = default_token
    if instance_type == 'server':
        config_data['bind_addr'] = addr
    elif instance_type == 'client':
        config_data['remote_addr'] = addr

    transport_config = {'type': transport_protocol}
    if transport_protocol == 'noise':
        private_key, public_key = _generate_noise_keys()
        transport_config['noise'] = {
            'local_private_key': private_key
        }
        if instance_type == 'client' and remote_public_key:
            transport_config['noise']['remote_public_key'] = remote_public_key

        metadata = _load_metadata()
        metadata.setdefault(f"{instance_type}_{instance_name}", {})['public_key'] = public_key
        _save_metadata(metadata)

    elif transport_protocol == 'tls':
        tls_config = {}
        if instance_type == 'server':
            # For server, generate PKCS#12 and use provided or generated password
            pfx_password = tls_pkcs12_password if tls_pkcs12_password else secrets.token_hex(16)
            pfx_path = _generate_tls_cert(f"{instance_type}_{instance_name}", pfx_password)
            tls_config['pkcs12'] = pfx_path
            tls_config['pkcs12_password'] = pfx_password
        elif instance_type == 'client':
            # For client, use provided trusted_root and hostname
            cert_path = _save_trusted_root_cert(instance_name, tls_trusted_root_content)
            if cert_path: tls_config['trusted_root'] = cert_path
            tls_config['hostname'] = "localhost"
        if tls_config: transport_config['tls'] = tls_config

    config_data['transport'] = transport_config

    if instance_type == 'server':
        config = {'server': config_data}
    elif instance_type == 'client':
        config = {'client': config_data}
    else: return False

    log_message(f"Generated config: {config}")
    with open(config_path, 'w') as f: toml.dump(config, f)
    log_message(f"Config file created at {config_path}")

    metadata = _load_metadata()
    metadata.setdefault(f"{instance_type}_{instance_name}", {})['auto_restart'] = auto_restart
    _save_metadata(metadata)
    load_all_from_disk()
    return True

def update_instance(instance_type, instance_name, new_addr, transport_protocol='tcp', remote_public_key=None, tls_trusted_root_content=None, tls_pkcs12_password=None):
    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
    if not os.path.exists(config_path):
        return False

    config = toml.load(config_path)
    instance_config = config.get(instance_type, {})

    if instance_type == 'server':
        instance_config['bind_addr'] = new_addr
    elif instance_type == 'client':
        instance_config['remote_addr'] = new_addr
    else:
        return False

    # Ensure transport structure exists
    if 'transport' not in instance_config:
        instance_config['transport'] = {}

    # Update transport type
    instance_config['transport']['type'] = transport_protocol

    # Clear old transport configs if switching protocol
    if transport_protocol != 'noise' and 'noise' in instance_config['transport']:
        del instance_config['transport']['noise']
    if transport_protocol != 'tls' and 'tls' in instance_config['transport']:
        del instance_config['transport']['tls']

    if transport_protocol == 'noise':
        if 'noise' not in instance_config['transport']:
            instance_config['transport']['noise'] = {}
        if instance_type == 'client' and remote_public_key:
            instance_config['transport']['noise']['remote_public_key'] = remote_public_key

    elif transport_protocol == 'tls':
        if 'tls' not in instance_config['transport']:
            instance_config['transport']['tls'] = {}

        if instance_type == 'server':
            # Regenerate cert if it doesn't exist for a server switching to TLS
            if not instance_config['transport']['tls'].get('pkcs12'):
                pfx_password = secrets.token_hex(16)
                pfx_path = _generate_tls_cert(f"{instance_type}_{instance_name}", pfx_password)
                instance_config['transport']['tls']['pkcs12'] = pfx_path
                instance_config['transport']['tls']['pkcs12_password'] = pfx_password
            else: # Respect existing values if present
                if tls_pkcs12_password: instance_config['transport']['tls']['pkcs12_password'] = tls_pkcs12_password

        elif instance_type == 'client':
            cert_path = _save_trusted_root_cert(instance_name, tls_trusted_root_content)
            if cert_path:
                instance_config['transport']['tls']['trusted_root'] = cert_path
            instance_config['transport']['tls']['hostname'] = "localhost"

    config[instance_type] = instance_config

    with open(config_path, 'w') as f:
        toml.dump(config, f)

    load_all_from_disk()
    return True

def regenerate_noise_keys(instance_type, instance_name):
    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
    if not os.path.exists(config_path):
        return False

    config = toml.load(config_path)
    if config[instance_type]['transport']['type'] != 'noise':
        return False

    private_key, public_key = _generate_noise_keys()
    config[instance_type]['transport']['noise']['local_private_key'] = private_key

    with open(config_path, 'w') as f:
        toml.dump(config, f)

    metadata = _load_metadata()
    metadata.setdefault(f"{instance_type}_{instance_name}", {})['public_key'] = public_key
    _save_metadata(metadata)
    load_all_from_disk()
    return True

def regenerate_tls_cert(instance_type, instance_name, password=None):
    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{instance_name}.toml")
    if not os.path.exists(config_path):
        return False

    config = toml.load(config_path)
    if config[instance_type]['transport']['type'] != 'tls':
        return False

    # Use existing password if not provided
    pfx_password = password
    if not pfx_password and instance_type == 'server':
         pfx_password = config[instance_type]['transport']['tls'].get('pkcs12_password')

    # Generate a new password if none exists
    if not pfx_password:
        pfx_password = secrets.token_hex(16)

    pfx_path = _generate_tls_cert(f"{instance_type}_{instance_name}", pfx_password)

    # Update config with new pfx path and password if it changed
    if instance_type == 'server':
        config[instance_type]['transport']['tls']['pkcs12'] = pfx_path
        config[instance_type]['transport']['tls']['pkcs12_password'] = pfx_password

    with open(config_path, 'w') as f:
        toml.dump(config, f)

    load_all_from_disk()
    return True

def remove_instance(instance_type, instance_name):
    stop_process(instance_type, instance_name)
    instance_key = f"{instance_type}_{instance_name}"
    config_path = os.path.join(CONFIG_DIR, f"{instance_key}.toml")
    log_path = os.path.join(CONFIG_DIR, f"{instance_key}.log")
    # Also remove TLS certificate and key if they exist
    cert_path = os.path.join(CONFIG_DIR, f"{instance_key}.crt")
    key_path = os.path.join(CONFIG_DIR, f"{instance_key}.key")
    pfx_path = os.path.join(CONFIG_DIR, f"{instance_key}.pfx")

    if os.path.exists(config_path): os.remove(config_path)
    if os.path.exists(log_path): os.remove(log_path)
    if os.path.exists(cert_path): os.remove(cert_path)
    if os.path.exists(key_path): os.remove(key_path)
    if os.path.exists(pfx_path): os.remove(pfx_path)

    metadata = _load_metadata()
    if instance_key in metadata: del metadata[instance_key]
    _save_metadata(metadata)
    load_all_from_disk()
    return True

def add_service(service_name, parent_instance, service_type, bind_addr=None, local_addr=None, token=None, protocol='tcp'):
    if service_name in get_all_services(): return False
    instance_type = 'server' if service_type == 'server_service' else 'client'
    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{parent_instance}.toml")
    if not os.path.exists(config_path): return False
    config = toml.load(config_path)

    service_data = {'type': protocol}
    if token: service_data['token'] = token

    if service_type == 'server_service':
        if not bind_addr: return False
        service_data['bind_addr'] = bind_addr
        config.setdefault(instance_type, {}).setdefault('services', {})[service_name] = service_data
    elif service_type == 'client_service':
        if not local_addr: return False
        service_data['local_addr'] = local_addr
        config.setdefault(instance_type, {}).setdefault('services', {})[service_name] = service_data
    else: return False

    with open(config_path, 'w') as f: toml.dump(config, f)
    load_all_from_disk()
    # Also update the cache with the new service protocol
    service_configurations_cache[service_name] = {
        'name': service_name,
        'service_type': service_type,
        'token': token,
        'local_addr': local_addr,
        'remote_addr': config.get(instance_type, {}).get('remote_addr'),
        'server_bind_addr': bind_addr,
        'parent_instance': parent_instance,
        'protocol': protocol
    }
    return True

def remove_service(service_name):
    details = get_all_services().get(service_name)
    if not details: return False

    parent_instance = details['parent_instance']
    instance_type = 'server' if details['service_type'] == 'server_service' else 'client'
    # stop_process(instance_type, parent_instance) # This is too disruptive, it stops the whole instance

    config_path = os.path.join(CONFIG_DIR, f"{instance_type}_{parent_instance}.toml")
    if not os.path.exists(config_path): return False

    config = toml.load(config_path)
    services = config.get(instance_type, {}).get('services', {})
    if service_name in services:
        del services[service_name]
        with open(config_path, 'w') as f: toml.dump(config, f)
    else: return False

    database.delete_traffic_data(service_name)
    load_all_from_disk()
    return True

def toggle_auto_restart(instance_type, instance_name):
    metadata = _load_metadata()
    instance_key = f"{instance_type}_{instance_name}"
    instance_meta = metadata.setdefault(instance_key, {})
    current_state = instance_meta.get('auto_restart', False)
    instance_meta['auto_restart'] = not current_state
    _save_metadata(metadata)
    return True

# --- Initialization ---
load_all_from_disk()
log_message("--- Initial cache populated ---")
