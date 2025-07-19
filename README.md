# Rathole Web Tunnel Manager

A web-based graphical interface to manage [rathole](https://github.com/rathole-org/rathole) tunnels. This panel allows users to easily add, remove, start, and stop rathole services, acting as either a rathole server for multiple defined services or as a rathole client for specific remote services.

## Features

*   **Web-Based UI:** Manage tunnels from your browser.
    *   Login page for secure access.
    *   Dashboard for viewing and managing all configured tunnel services.
    *   Settings page to change panel login credentials.
*   **Rathole Integration:**
    *   **Panel Hosted Services:** Configure the panel to act as a rathole server, exposing multiple local or network-accessible services through unique public ports.
    *   **Remote Target Services:** Configure the panel to act as a rathole client, connecting to a remote service and exposing it through a rathole server (either the panel's own or an external one).
    *   Automatic token generation (optional).
    *   Start, stop, and remove individual tunnel services.
    *   View status of services and the main rathole server instance.
*   **Automatic Installation (Ubuntu):**
    *   Includes an `install.sh` script to automate setup on Ubuntu systems.
    *   Installs all required dependencies, including the rathole binary.
    *   Sets up the Python Flask application.
    *   Generates a random admin username and password for initial login.
    *   Provides guidance for firewall and systemd service configuration.

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
sudo bash install.sh "$(pwd)"
```

The script will:
- Install dependencies like Python, Pip, and Certbot.
- Download and install the `rathole` binary.
- Set up the application in `/opt/my-tunnel-manager`.
- Create a Python virtual environment.
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

### 3. (Optional) Set Up a Domain and SSL

To access your panel via a domain with a valid SSL certificate:
1.  **Point your domain's A record** to your server's IP address.
2.  Navigate to the **Settings** page in the panel.
3.  Enter your domain name in the **Domain & SSL Configuration** section and click **Save Domain**.
4.  The SSL status will appear. Click the **Generate Certificate** button.
5.  The panel will use Certbot to obtain a certificate from Let's Encrypt. The logs will be displayed in the text area.
6.  If successful, a **Restart Program** button will appear. Click it.
7.  The program will restart. After a few seconds, your browser will be redirected to the `https` version of your panel.

### 4. Adding and Managing Instances

-   **Instances** are running `rathole` processes. You can have multiple server and client instances.
-   Click the **Add Server Instance** or **Add Client Instance** buttons to create a new instance.
    -   **Server Instance:** Listens for connections from a `rathole` client.
    -   **Client Instance:** Connects to a remote `rathole` server.
-   You can **Start**, **Stop**, **Remove**, and **Edit** instances from the dashboard.

### 5. Adding and Managing Services

-   **Services** are the individual tunnels within an instance.
-   Click the **Add Port** button on an instance card to add a new service.
-   You can **Remove** services from the service list on each instance card.

### Command-Line Interface (CLI)

The `tunnel-manager-web` command provides a way to manage the application from the command line.

**Change a User's Password:**
```bash
sudo tunnel-manager-web password <username> <new_password>
```
Example:
```bash
sudo tunnel-manager-web password admin myNewSecurePassword123
```

**Reset the Domain Name:**
This command deletes the configured domain, reverting the panel to HTTP on the next restart.
```bash
sudo tunnel-manager-web reset-domain
```

**Manage the Web Service:**
You can start, stop, and restart the web panel using the following commands:
```bash
sudo tunnel-manager-web start
sudo tunnel-manager-web stop
sudo tunnel-manager-web restart
```

## TODO / Future Enhancements

*   More robust status checking for rathole processes.
*   Utilize rathole's hot-reloading for config changes where possible.
*   Detailed logging viewable in the UI.
*   User-specific tunnels if multi-user support is added.
*   Support for TLS/Noise configuration for rathole transport.
*   Package as a Docker container.
