import subprocess
import re
import os
import time

# --- Logging ---
PANEL_LOG_FILE = os.path.join("/app", 'instance', 'panel.log')
def log_message(message):
    try:
        os.makedirs(os.path.dirname(PANEL_LOG_FILE), exist_ok=True)
        if not os.path.exists(PANEL_LOG_FILE):
            with open(PANEL_LOG_FILE, "w") as f:
                pass
            os.chmod(PANEL_LOG_FILE, 0o666)
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open(PANEL_LOG_FILE, "a") as f:
            f.write(f"[{timestamp} UTC] [iptables_manager] {message}\n")
    except Exception as e:
        print(f"!!! FAILED TO WRITE TO LOG FILE {PANEL_LOG_FILE}: {e} !!!")
        print(f"Original log message was: {message}")

# --- Module Code ---
CHAIN_NAME = "RATHOLE_TRAFFIC"

def run_command(command):
    """Executes a shell command with sudo and returns its output."""
    log_message(f"Executing command: {' '.join(['sudo'] + command)}")
    try:
        result = subprocess.run(['sudo'] + command, capture_output=True, text=True, check=True)
        if result.stderr:
            log_message(f"Command successful, but stderr has data: {result.stderr.strip()}")
        log_message(f"Command stdout: {result.stdout.strip()}")
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        log_message(f"!!! ERROR executing command '{' '.join(command)}': {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        log_message("!!! FATAL ERROR: 'sudo' command not found.")
        return None

def setup_iptables_chain():
    """Creates the custom chain if it doesn't exist and ensures jumps from INPUT/OUTPUT."""
    log_message("Setting up iptables chains...")
    existing_chains = run_command(['iptables', '-L'])
    if existing_chains is not None and CHAIN_NAME not in existing_chains:
        log_message(f"Creating new iptables chain: {CHAIN_NAME}")
        run_command(['iptables', '-N', CHAIN_NAME])

    input_rules = run_command(['iptables', '-S', 'INPUT'])
    if input_rules is not None and f"-A INPUT -j {CHAIN_NAME}" not in input_rules:
        log_message(f"Adding jump from INPUT to {CHAIN_NAME}")
        run_command(['iptables', '-I', 'INPUT', '-j', CHAIN_NAME])

    output_rules = run_command(['iptables', '-S', 'OUTPUT'])
    if output_rules is not None and f"-A OUTPUT -j {CHAIN_NAME}" not in output_rules:
        log_message(f"Adding jump from OUTPUT to {CHAIN_NAME}")
        run_command(['iptables', '-I', 'OUTPUT', '-j', CHAIN_NAME])

    log_message("iptables chains setup complete.")

def add_traffic_rules(service_name, port):
    """Adds iptables rules to count traffic for a specific service port."""
    if not service_name or not port: return False

    comment = f"rathole_svc_{service_name}"
    log_message(f"Adding rules for service '{service_name}' on port {port} with comment '{comment}'")

    # Using -I to insert at the top to make sure they are hit before any potential blocking rules
    run_command(['iptables', '-I', CHAIN_NAME, '-p', 'tcp', '--dport', str(port), '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'])
    run_command(['iptables', '-I', CHAIN_NAME, '-p', 'udp', '--dport', str(port), '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'])
    run_command(['iptables', '-I', CHAIN_NAME, '-p', 'tcp', '--sport', str(port), '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'])
    run_command(['iptables', '-I', CHAIN_NAME, '-p', 'udp', '--sport', str(port), '-m', 'comment', '--comment', comment, '-j', 'ACCEPT'])

    log_message(f"Finished adding rules for service '{service_name}'.")
    return True

def remove_traffic_rules(service_name):
    """Removes all iptables rules associated with a specific service by comment."""
    if not service_name: return False

    comment = f"rathole_svc_{service_name}"
    log_message(f"Attempting to remove rules for service '{service_name}' with comment '{comment}'")

    while True:
        rules = run_command(['iptables', '-L', CHAIN_NAME, '--line-numbers', '-v', '-n'])
        if not rules: break

        rule_to_delete = None
        for line in rules.split('\n'):
            if comment in line:
                rule_to_delete = line.split()[0]
                break

        if rule_to_delete:
            log_message(f"Deleting rule number {rule_to_delete} for service '{service_name}'...")
            run_command(['iptables', '-D', CHAIN_NAME, rule_to_delete])
            time.sleep(0.1) # Brief pause to allow iptables to process deletion
        else:
            break

    log_message(f"Finished removing rules for service '{service_name}'.")
    return True

def get_traffic_stats():
    """
    Parses iptables output to get traffic stats for all monitored services.
    Returns a dictionary: {'service_name': {'sent': bytes, 'recv': bytes}}
    """
    stats = {}
    # The '-n' flag is crucial to prevent iptables from resolving port numbers to service names (e.g., 80 to "http"),
    # which can break the regex matching if the service name is not a number.
    rules_output = run_command(['iptables', '-L', CHAIN_NAME, '-v', '-n', '-x'])
    if not rules_output: return {}

    # Regex Explanation:
    # - \s*\d+\s+      - Matches the packet count column (and leading whitespace)
    # - (\d+)\s+        - CAPTURES the bytes column
    # - .*?             - Non-greedy match for any characters (source, dest, etc.)
    # - (spt|dpt)     - Matches either "spt" or "dpt"
    # - :(\S+)        - Matches and CAPTURES the port number/name
    # - .*?             - Non-greedy match for other options
    # - \/\*\s*         - Matches the start of the iptables comment "/* "
    # - rathole_svc_    - Matches the prefix for our service identifier
    # - (\S+)           - CAPTURES the service name (non-whitespace)
    # - \s*\*\/         - Matches the end of the comment " */"
    pattern = re.compile(r'^\s*\d+\s+(\d+)\s+.*?\s(spt|dpt):(\S+).*?\/\*\s*rathole_svc_(\S+)\s*\*\/')

    for line in rules_output.split('\n'):
        match = pattern.search(line) # Use search instead of match for flexibility
        if not match: continue

        byte_count, direction, _, service_name = match.groups()
        byte_count = int(byte_count)

        stats.setdefault(service_name, {'sent': 0, 'recv': 0})

        # The direction is determined by the rule's target port (dpt/spt)
        # - A packet leaving the machine (OUTPUT chain) with a 'spt' matching the service port is SENT traffic.
        # - A packet entering the machine (INPUT chain) with a 'dpt' matching the service port is RECV traffic.
        # Since we have rules for both spt and dpt, we need to correctly identify them.
        if direction == 'dpt': # Destination port -> received by service
            stats[service_name]['recv'] += byte_count
        elif direction == 'spt': # Source port -> sent by service
            stats[service_name]['sent'] += byte_count

    return stats

def reset_traffic_counters(service_name):
    """Resets the traffic counters for a specific service by comment."""
    if not service_name: return False

    comment = f"rathole_svc_{service_name}"
    log_message(f"Resetting traffic counters for service '{service_name}' with comment '{comment}'")

    # The -Z command needs to be applied to the chain and will zero counters for all rules.
    # To reset for a specific service, we must iterate through rules and zero them one by one.
    # This is complex. A simpler approach is to use -Z on the whole chain, which is often acceptable.
    # For this implementation, we will zero the entire custom chain.
    # A more granular approach would require finding the specific rule numbers and zeroing them.

    # Find the rules with the specific comment and zero them.
    rules = run_command(['iptables', '-L', CHAIN_NAME, '--line-numbers', '-v', '-n'])
    if not rules: return True # Chain is empty or does not exist

    rule_numbers_to_zero = []
    for line in rules.split('\n'):
        if comment in line:
            parts = line.strip().split()
            if parts:
                rule_numbers_to_zero.append(parts[0])

    if not rule_numbers_to_zero:
        log_message(f"No rules found for service '{service_name}' to reset.")
        return False

    # Zeroing each rule by its number
    for rule_num in sorted(rule_numbers_to_zero, key=int, reverse=True):
        run_command(['iptables', '-Z', CHAIN_NAME, rule_num])

    log_message(f"Successfully reset traffic counters for service '{service_name}'.")
    return True
