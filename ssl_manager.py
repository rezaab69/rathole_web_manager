import subprocess
import os
import time

def run_command(command, working_dir=None):
    """Executes a shell command and returns its output and exit code."""
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=working_dir,
            timeout=300  # 5-minute timeout for Certbot
        )
        return process.stdout + process.stderr, process.returncode
    except subprocess.TimeoutExpired:
        return "Command timed out after 5 minutes.", -1
    except Exception as e:
        return f"An unexpected error occurred: {e}", -1

def manage_firewall(action, port="80"):
    """Opens or closes a port using iptables."""
    rule_spec = ['-p', 'tcp', '--dport', port, '-j', 'ACCEPT', '-m', 'comment', '--comment', 'certbot_http']
    if action == 'open':
        # Use -I to insert the rule at the top of the INPUT chain
        command = ['sudo', 'iptables', '-I', 'INPUT'] + rule_spec
        message = f"Opening port {port} for Let's Encrypt verification."
    elif action == 'close':
        # Use -D to delete the rule
        command = ['sudo', 'iptables', '-D', 'INPUT'] + rule_spec
        message = f"Closing port {port} after verification."
    else:
        return "Invalid firewall action.", -1

    output, exit_code = run_command(command)
    if exit_code != 0:
        return f"Failed to {action} port {port}. IPTables error: {output}", -1
    return message, 0

def generate_certificate(domain_name):
    """
    Automates the process of obtaining a Let's Encrypt SSL certificate using Certbot.
    """
    logs = []

    # --- Step 1: Open port 80 ---
    log_entry, exit_code = manage_firewall('open')
    logs.append(log_entry)
    if exit_code != 0:
        return False, "\n".join(logs)

    # --- Step 2: Run Certbot ---
    certbot_command = [
        'sudo', 'certbot', 'certonly',
        '--standalone',
        '--non-interactive',
        '--agree-tos',
        '--email', 'admin@' + domain_name, # A generic email
        '-d', domain_name
    ]
    logs.append(f"Executing Certbot for domain: {domain_name}...")

    certbot_output, certbot_exit_code = run_command(certbot_command)
    logs.append("--- Certbot Output ---")
    logs.append(certbot_output)
    logs.append("--- End Certbot Output ---")

    # --- Step 3: Close port 80 ---
    log_entry, _ = manage_firewall('close')
    logs.append(log_entry)

    # --- Step 4: Check result and provide final status ---
    if certbot_exit_code == 0:
        success = True
        cert_path = f'/etc/letsencrypt/live/{domain_name}/fullchain.pem'
        key_path = f'/etc/letsencrypt/live/{domain_name}/privkey.pem'
        logs.append("\nSUCCESS! Certificate generated and stored at:")
        logs.append(f"  - Certificate: {cert_path}")
        logs.append(f"  - Private Key: {key_path}")
        logs.append("\nPlease configure your web server to use these files.")
    else:
        success = False
        logs.append("\nERROR: Certbot failed. Please review the logs above for details.")

    return success, "\n".join(logs)
