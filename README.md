# Rathole Web Tunnel Manager

A web-based graphical interface to manage [rathole](https://github.com/rathole-org/rathole) tunnels. This panel allows users to easily add, remove, start, and stop rathole services, acting as either a rathole server for multiple defined services or as a rathole client for specific remote services.

## Features

*   **Web-Based UI:** Manage tunnels from your browser.
    *   Secure login page.
    *   Dashboard for viewing and managing all server and client instances.
    *   Real-time status updates for instances (active, stopped, etc.) and traffic.
    *   Settings page to change panel login credentials.
*   **Rathole Instance Management:**
    *   Run multiple `rathole` server and client instances independently.
    *   Add, remove, start, stop, and edit instances.
    *   Configure auto-restart for each instance on failure.
*   **Secure Transport Protocols:**
    *   Full support for **TCP**, **Noise**, and **TLS** transport protocols.
    *   **Noise:** Automatic key pair generation for secure, modern connections.
    *   **TLS:** Automatic on-demand certificate generation and management for server instances.
*   **Service Management:**
    *   Add and remove individual port forwarding services (tunnels) to any instance.
*   **Traffic Monitoring:**
    *   View sent and received traffic for each service in real-time.
    *   Reset traffic counters for individual services.
*   **Automatic Installation (Ubuntu/Debian):**
    *   Includes an `install.sh` script to automate setup.
    *   Installs dependencies, downloads the `rathole` binary, and sets up the Python environment.
    *   Generates a random admin password for initial login.
    *   Sets up `iptables` rules required for traffic monitoring.
    *   Creates a `systemd` service for easy management.

## Installation

These instructions are for a Debian-based Linux distribution (like Ubuntu).

### 1. Clone the Repository

First, clone this repository to your server.

```bash
git clone https://github.com/rezaab69/rathole_management.git
cd rathole_management
```

### 2. Run the Installation Script

The `install.sh` script will set up the application, its dependencies, and a `systemd` service to run it automatically.

```bash
sudo bash install.sh
```

The script will:
- Install dependencies like Python, Pip, and the `build-essential` package.
- Download and install the latest `rathole` binary to `/usr/local/bin`.
- Set up the application in `/opt/my-tunnel-manager`.
- Create a Python virtual environment and install required packages.
- Generate a random admin password.
- Set up `iptables` rules for traffic monitoring.
- Create and enable a `systemd` service to run the panel.

At the end of the script, it will display the **URL**, **admin username**, and **admin password**. **Save this password!**

### 3. Configure Your Firewall

The installer does not automatically open firewall ports. You must open the panel port (default `5001`) and any ports you intend to use for your tunnels.

For `ufw`:
```bash
# Allow the panel
sudo ufw allow 5001/tcp

# Allow a tunnel port (example)
sudo ufw allow 7000/tcp

# Enable the firewall
sudo ufw enable
```

## Usage

### 1. Initial Login

Access the web panel using the URL provided at the end of the installation. Log in with the `admin` username and the generated password.

### 2. Change Your Password

Navigate to the **Settings** page and change your password immediately.

### 3. Adding and Managing Instances

-   **Instances** are running `rathole` processes. You can have multiple server and client instances.
-   Click the **Add Server Instance** or **Add Client Instance** buttons to create a new instance.
-   Select the desired **Transport Protocol** (TCP, Noise, or TLS).
    -   For **Noise** servers, keys are generated automatically. For clients, you must provide the server's public key.
    -   For **TLS** servers, a self-signed certificate is generated automatically. You can copy the certificate content from the modal to configure your clients.
-   You can **Start**, **Stop**, **Remove**, and **Edit** instances from the dashboard.
-   Toggle the **Auto-Restart** switch to enable or disable automatic restarts for an instance if its process fails.

### 4. Adding and Managing Services

-   **Services** are the individual tunnels within an instance.
-   Click the **Add Port** button on an instance card to add a new service.
-   You can **Remove** services from the service list on each instance card.

### 5. Monitoring Traffic

-   The **Ports Traffic** section on the dashboard shows the data sent and received for each active service.
-   Click the **Reset** button to clear the traffic counters for a specific service.

### Command-Line Interface (CLI)

The `tunnel-manager-web` command provides a way to manage the application from the command line. It must be run with `sudo`.

**Change a User's Password:**
```bash
sudo tunnel-manager-web password <username> <new_password>
```
Example:
```bash
sudo tunnel-manager-web password admin myNewSecurePassword123
```

**Manage the Web Service:**
You can start, stop, and restart the web panel using the following commands:
```bash
sudo tunnel-manager-web start
sudo tunnel-manager-web stop
sudo tunnel-manager-web restart
```

## Technologies Used

*   **Backend:** Python, Flask
*   **Frontend:** HTML, CSS, JavaScript, Bootstrap 5
*   **WSGI Server:** Gunicorn
*   **Process Management:** `systemd`
*   **Tunneling:** `rathole`
*   **Networking:** `iptables` (for traffic accounting)

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any bugs, feature requests, or improvements.

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/YourFeature`).
3.  Commit your changes (`git commit -m 'Add some feature'`).
4.  Push to the branch (`git push origin feature/YourFeature`).
5.  Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## TODO / Future Enhancements

*   More robust status checking for rathole processes.
*   Utilize rathole's hot-reloading for config changes where possible.
*   Detailed logging viewable in the UI.
*   User-specific tunnels if multi-user support is added.
*   Support for TLS/Noise configuration for rathole transport.
*   Package as a Docker container.
