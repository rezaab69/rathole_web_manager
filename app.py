from flask import Flask, render_template, redirect, url_for, session, request, flash, Response, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import secrets
import database # For user auth only now
import rathole_manager
import health_checker
import json
import time
import iptables_manager
import traffic_manager

database.init_db()
app = Flask(__name__)
app.config['VERSION'] = "1.0.0"

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))

# --- Rate Limiting Setup ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# --- Request Handling ---
@app.before_request
def before_request():
    # If the app is behind a proxy, the proxy will set the X-Forwarded-Proto header.
    # We need to trust this header to know if the original request was secure.
    if request.headers.get('X-Forwarded-Proto') == 'http':
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

    if app.config.get('SESSION_COOKIE_SECURE') and not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

# --- Custom Jinja Filter ---
@app.template_filter('human_readable_bytes')
def human_readable_bytes(value, suffix="B"):
    """Converts a number of bytes to a human-readable format (e.g., KB, MB)."""
    try:
        value = float(value)
    except (ValueError, TypeError):
        return "N/A"

    if value == 0:
        return "0 B"

    for unit in ["", "K", "M", "G", "T", "P", "E", "Z"]:
        if abs(value) < 1024.0:
            return f"{value:3.1f} {unit}{suffix}"
        value /= 1024.0
    return f"{value:.1f} Y{suffix}"

# --- Routes ---

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if database.verify_user(username, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    server_instances = rathole_manager.get_all_instances('server')
    client_instances = rathole_manager.get_all_instances('client')
    tunnels = rathole_manager.get_all_services()

    for name, server in server_instances.items():
        if server.get('transport_protocol') == 'tls':
            server['tls_cert_content'] = rathole_manager._get_server_cert_content(name)

    return render_template('dashboard.html', username=session['username'], tunnels=tunnels, servers=server_instances, clients=client_instances)

@app.route('/view_cert/<instance_name>')
def view_cert(instance_name):
    if 'username' not in session: return redirect(url_for('login'))
    cert_content = rathole_manager._get_server_cert_content(instance_name)
    if cert_content:
        return Response(cert_content, mimetype='text/plain')
    else:
        flash(f"Certificate for '{instance_name}' not found.", 'danger')
        return redirect(url_for('dashboard'))

@app.route('/add_instance', methods=['POST'])
def add_instance():
    if 'username' not in session: return redirect(url_for('login'))

    instance_type = request.form.get('instance_type')
    port = request.form.get('port')
    name = request.form.get('name') or port
    token = request.form.get('token')
    if not token:
        token = "RezaAb"
    auto_restart = request.form.get('auto_restart') == 'on'
    transport_protocol = request.form.get('transport_protocol', 'tcp')
    tls_pkcs12_password = request.form.get('tls_pkcs12_password')
    tls_trusted_root_content = request.form.get('tls_trusted_root_content')

    if instance_type == 'server':
        addr = f"0.0.0.0:{port}"
        if all([name, port]):
            if rathole_manager.add_instance('server', name, addr, default_token=token, auto_restart=auto_restart, transport_protocol=transport_protocol, tls_pkcs12_password=tls_pkcs12_password):
                flash(f"New server instance '{name}' created.", 'success')
            else:
                flash(f"Failed to create server instance '{name}'. It might already exist.", 'danger')
        else:
            flash("Port is required for new server instances.", 'danger')

    elif instance_type == 'client':
        address = request.form.get('address')
        addr = f"{address}:{port}"
        remote_public_key = request.form.get('remote_public_key')
        if all([name, address, port]):
            if rathole_manager.add_instance('client', name, addr, default_token=token, auto_restart=auto_restart, transport_protocol=transport_protocol, remote_public_key=remote_public_key, tls_trusted_root_content=tls_trusted_root_content):
                flash(f"New client instance '{name}' created.", 'success')
            else:
                flash(f"Failed to create client instance '{name}'. It might already exist.", 'danger')
        else:
            flash("Address and Port are required for new client instances.", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/add_service', methods=['POST'])
def add_service():
    if 'username' not in session: return redirect(url_for('login'))

    parent_instance = request.form.get('parent_instance')
    instance_type = request.form.get('instance_type')
    port = request.form.get('port')
    service_name = request.form.get('name') or port
    token = request.form.get('token')
    protocol = request.form.get('protocol', 'tcp')

    if instance_type == 'server':
        service_type = 'server_service'
        bind_addr = f"0.0.0.0:{port}"
        if all([service_name, parent_instance, port]):
            if rathole_manager.add_service(service_name, parent_instance, service_type, bind_addr=bind_addr, token=token, protocol=protocol):
                iptables_manager.add_traffic_rules(service_name, port)
                flash(f"Service '{service_name}' added to server '{parent_instance}'. Restart instance to apply.", 'success')
            else:
                flash(f"Failed to add service '{service_name}'. It might already exist.", 'danger')
        else:
            flash("Service Name/Port and Parent Instance are required.", 'danger')

    elif instance_type == 'client':
        service_type = 'client_service'
        local_addr = f"0.0.0.0:{port}"
        if all([service_name, parent_instance, port]):
            if rathole_manager.add_service(service_name, parent_instance, service_type, local_addr=local_addr, token=token, protocol=protocol):
                iptables_manager.add_traffic_rules(service_name, port)
                flash(f"Service '{service_name}' added to client '{parent_instance}'. Restart instance to apply.", 'success')
            else:
                flash(f"Failed to add service '{service_name}'. It might already exist.", 'danger')
        else:
            flash("Service Name/Port and Parent Instance are required.", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/api/instance/start', methods=['POST'])
def api_start_instance():
    data = request.json
    instance_type = data.get('instance_type')
    instance_name = data.get('instance_name')
    if not all([instance_type, instance_name]):
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400
    
    success = rathole_manager.start_instance(instance_type, instance_name)
    if success:
        return jsonify({'status': 'success', 'message': f'{instance_name} started.'})
    else:
        return jsonify({'status': 'error', 'message': f'Failed to start {instance_name}.'}), 500

@app.route('/api/instance/stop', methods=['POST'])
def api_stop_instance():
    data = request.json
    instance_type = data.get('instance_type')
    instance_name = data.get('instance_name')
    if not all([instance_type, instance_name]):
        return jsonify({'status': 'error', 'message': 'Missing parameters'}), 400

    success = rathole_manager.stop_process(instance_type, instance_name)
    if success:
        return jsonify({'status': 'success', 'message': f'{instance_name} stopped.'})
    else:
        return jsonify({'status': 'error', 'message': f'Failed to stop {instance_name}.'}), 500

@app.route('/start_instance/<instance_type>/<instance_name>')
def start_instance(instance_type, instance_name):
    if 'username' not in session: return redirect(url_for('login'))
    if rathole_manager.start_instance(instance_type, instance_name):
        flash(f"{instance_type.capitalize()} instance '{instance_name}' started.", 'success')
    else:
        flash(f"Failed to start {instance_type} instance '{instance_name}'.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/stop_instance/<instance_type>/<instance_name>')
def stop_instance(instance_type, instance_name):
    if 'username' not in session: return redirect(url_for('login'))
    if rathole_manager.stop_process(instance_type, instance_name):
        flash(f"{instance_type.capitalize()} instance '{instance_name}' stopped.", 'success')
    else:
        flash(f"Failed to stop {instance_type} instance '{instance_name}'.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/remove_instance/<instance_type>/<instance_name>')
def remove_instance(instance_type, instance_name):
    if 'username' not in session: return redirect(url_for('login'))

    # First, get all services associated with this instance
    all_tunnels = rathole_manager.get_all_services()
    services_to_remove = [s_name for s_name, s_details in all_tunnels.items() if s_details['parent_instance'] == instance_name]

    # Try to remove the instance from rathole configuration
    if rathole_manager.remove_instance(instance_type, instance_name):
        # If successful, remove associated iptables rules
        for service_name in services_to_remove:
            iptables_manager.remove_traffic_rules(service_name)
        flash(f"{instance_type.capitalize()} instance '{instance_name}' and associated rules removed.", 'success')
    else:
        flash(f"Failed to remove {instance_type} instance '{instance_name}'.", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/toggle_auto_restart/<instance_type>/<instance_name>')
def toggle_auto_restart(instance_type, instance_name):
    if 'username' not in session: return redirect(url_for('login'))
    if rathole_manager.toggle_auto_restart(instance_type, instance_name):
        flash(f"Auto-restart setting for '{instance_name}' has been toggled.", 'success')
    else:
        flash(f"Failed to toggle auto-restart for '{instance_name}'.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/edit_instance', methods=['POST'])
def edit_instance():
    if 'username' not in session: return redirect(url_for('login'))

    instance_type = request.form.get('instance_type')
    instance_name = request.form.get('instance_name')
    transport_protocol = request.form.get('transport_protocol', 'tcp')
    remote_public_key = request.form.get('remote_public_key')
    tls_trusted_root_content = request.form.get('tls_trusted_root_content')
    tls_pkcs12_password = request.form.get('tls_pkcs12_password')

    if instance_type == 'server':
        port = request.form.get('port')
        if all([instance_name, port]):
            addr = f"0.0.0.0:{port}"
            if rathole_manager.update_instance(instance_type, instance_name, addr, transport_protocol=transport_protocol, tls_pkcs12_password=tls_pkcs12_password):
                flash(f"Server instance '{instance_name}' updated.", 'success')
            else:
                flash(f"Failed to update server instance '{instance_name}'.", 'danger')
        else:
            flash("Port is required for server instances.", 'danger')

    elif instance_type == 'client':
        address = request.form.get('address')
        port = request.form.get('port')
        if all([instance_name, address, port]):
            addr = f"{address}:{port}"
            if rathole_manager.update_instance(instance_type, instance_name, addr, transport_protocol=transport_protocol, remote_public_key=remote_public_key, tls_trusted_root_content=tls_trusted_root_content):
                flash(f"Client instance '{instance_name}' updated.", 'success')
            else:
                flash(f"Failed to update client instance '{instance_name}'.", 'danger')
        else:
            flash("Address and Port are required for client instances.", 'danger')

    return redirect(url_for('dashboard'))

@app.route('/regenerate_key/<instance_type>/<instance_name>')
def regenerate_key(instance_type, instance_name):
    if 'username' not in session: return redirect(url_for('login'))
    if rathole_manager.regenerate_noise_keys(instance_type, instance_name):
        flash(f"Noise keys for '{instance_name}' have been regenerated.", 'success')
    else:
        flash(f"Failed to regenerate noise keys for '{instance_name}'.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/regenerate_cert/<instance_type>/<instance_name>')
def regenerate_cert(instance_type, instance_name):
    if 'username' not in session: return redirect(url_for('login'))
    if rathole_manager.regenerate_tls_cert(instance_type, instance_name):
        flash(f"TLS certificate for '{instance_name}' has been regenerated.", 'success')
    else:
        flash(f"Failed to regenerate TLS certificate for '{instance_name}'.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/remove_service/<service_name>')
def remove_service(service_name):
    if 'username' not in session: return redirect(url_for('login'))
    if rathole_manager.remove_service(service_name):
        iptables_manager.remove_traffic_rules(service_name)
        flash(f"Service '{service_name}' removed. Restart the parent instance to apply changes.", 'success')
    else:
        flash(f"Failed to remove service '{service_name}'.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/reset_traffic/<service_name>')
def reset_traffic(service_name):
    if 'username' not in session: return redirect(url_for('login'))
    if iptables_manager.reset_traffic_counters(service_name):
        flash(f"Traffic counters for service '{service_name}' have been reset.", 'success')
        database.delete_traffic_data(service_name)
    else:
        flash(f"Failed to reset traffic counters for '{service_name}'.", 'danger')
    return redirect(url_for('dashboard'))

@app.route('/api/status')
# Exempt the frequent status polling endpoint from rate limiting
@limiter.exempt
def api_status():
    if 'username' not in session:
        return jsonify({}), 401 # Return empty object or an error

    servers = rathole_manager.get_all_instances('server')
    clients = rathole_manager.get_all_instances('client')
    tunnels = rathole_manager.get_all_services()

    # Convert traffic data to human-readable format for the frontend
    for instances in [servers, clients]:
        for instance in instances.values():
            if 'services' in instance:
                for service in instance['services'].values():
                    if 'traffic' in service:
                        service['traffic']['sent_hr'] = human_readable_bytes(service['traffic'].get('sent', 0))
                        service['traffic']['recv_hr'] = human_readable_bytes(service['traffic'].get('recv', 0))

    return jsonify(servers=servers, clients=clients, tunnels=tunnels)

def stream_updates():
    if 'username' not in session:
        return Response(status=401)

    def generate():
        while True:
            server_instances = rathole_manager.get_all_instances('server')
            client_instances = rathole_manager.get_all_instances('client')

            # Convert instance data to a JSON-serializable format
            data = {
                'servers': {name: dict(instance) for name, instance in server_instances.items()},
                'clients': {name: dict(instance) for name, instance in client_instances.items()}
            }

            # Apply the human_readable_bytes filter manually before sending
            for instance_type in ['servers', 'clients']:
                for name, instance in data[instance_type].items():
                    traffic_data = instance.get('traffic', {})
                    instance['traffic'] = traffic_data # Ensure traffic key exists
                    instance['traffic']['sent_hr'] = human_readable_bytes(traffic_data.get('sent', 0))
                    instance['traffic']['recv_hr'] = human_readable_bytes(traffic_data.get('recv', 0))
                    for service_name, service in instance.get('services', {}).items():
                        service_traffic_data = service.get('traffic', {})
                        service['traffic'] = service_traffic_data # Ensure traffic key exists
                        service['traffic']['sent_hr'] = human_readable_bytes(service_traffic_data.get('sent', 0))
                        service['traffic']['recv_hr'] = human_readable_bytes(service_traffic_data.get('recv', 0))

            yield f"data: {json.dumps(data)}"
            time.sleep(2) # Update every 2 seconds

    return Response(generate(), mimetype='text/event-stream')

@app.route('/stream')
def stream():
    return stream_updates()

# --- User Routes ---

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'username' not in session: return redirect(url_for('login'))
    username = session['username']

    if request.method == 'POST':
        # Handle password change
        if 'new_password' in request.form:
            current_password, new_password, confirm_password = request.form['current_password'], request.form['new_password'], request.form['confirm_password']
            if not database.verify_user(username, current_password):
                flash('Current password is incorrect.', 'danger')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'danger')
            elif len(new_password) < 8:
                flash('New password must be at least 8 characters long.', 'danger')
            else:
                if database.update_password(username, new_password):
                    flash('Password updated successfully!', 'success')
                else:
                    flash('Failed to update password. Please try again.', 'danger')

        # Handle domain name update
        elif 'domain_name' in request.form:
            domain = request.form['domain_name']
            if database.set_setting('domain_name', domain):
                flash('Domain name updated successfully!', 'success')
            else:
                flash('Failed to update domain name.', 'danger')

        return redirect(url_for('settings'))

    # Render the settings page
    ssl_logs = session.pop('ssl_logs', None)
    domain_name = database.get_setting('domain_name')
    return render_template('settings.html', username=username, ssl_logs=ssl_logs, domain_name=domain_name)

@app.route('/generate_ssl', methods=['POST'])
def generate_ssl():
    if 'username' not in session: return redirect(url_for('login'))

    domain_name = database.get_setting('domain_name')
    if not domain_name:
        flash('Please set and save a domain name before generating an SSL certificate.', 'danger')
        return redirect(url_for('settings'))

    import ssl_manager
    success, logs = ssl_manager.generate_certificate(domain_name)

    return jsonify({'success': success, 'logs': logs})

@app.route('/ssl_status')
def ssl_status():
    if 'username' not in session:
        return Response(status=401)

    domain = request.args.get('domain')
    if not domain:
        return jsonify({'status': 'No domain provided'})

    cert_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
    if os.path.exists(cert_path):
        return jsonify({'status': 'Active'})
    else:
        return jsonify({'status': 'Not Found'})

@app.route('/restart_program', methods=['POST'])
def restart_program():
    if 'username' not in session:
        return Response(status=401)

    def restart():
        time.sleep(1)
        os._exit(0)

    import threading
    threading.Thread(target=restart).start()

    return jsonify({'status': 'restarting'})

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/init_db')
def init_db_route():
    database.init_db()
    return 'database initialized'

@app.route('/create_user')
def create_user():
    create_initial_user('admin', 'password')
    return 'user created'

def create_initial_user(username, password):
    if not database.get_user(username):
        return database.add_user(username, password)
    return True

if __name__ == '__main__':
    health_checker.start_background_checker()
    traffic_manager.start_traffic_updater()

    domain = database.get_setting('domain_name')
    ssl_context = None
    if domain:
        cert_path = f'/etc/letsencrypt/live/{domain}/fullchain.pem'
        key_path = f'/etc/letsencrypt/live/{domain}/privkey.pem'
        if os.path.exists(cert_path) and os.path.exists(key_path):
            ssl_context = (cert_path, key_path)
            app.config['SESSION_COOKIE_SECURE'] = True
            app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
            print(f"--- Found SSL cert for {domain}, starting with HTTPS ---")
        else:
            print(f"--- SSL cert for {domain} not found, starting with HTTP ---")
    else:
        print("--- No domain configured, starting with HTTP ---")

    app.run(
        debug=True,
        host='0.0.0.0',
        port=5001,
        use_reloader=False,
        ssl_context=ssl_context
    )
