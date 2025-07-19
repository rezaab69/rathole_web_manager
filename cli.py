#!/usr/bin/env python3
import argparse
import database
import os
import sys

# Ensure the script can find the database module
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def change_password(args):
    """Handler for the 'password' subcommand."""
    if database.update_password(args.username, args.new_password):
        print(f"Successfully changed password for user '{args.username}'.")
    else:
        print(f"Error: Could not change password for user '{args.username}'. User may not exist.")

def reset_domain(args):
    """Handler for the 'reset-domain' subcommand."""
    if database.delete_setting('domain_name'):
        print("Successfully reset the domain. The application will revert to HTTP on next restart.")
    else:
        print("Error: Could not reset domain.")

def service_control(action):
    """Handles start, stop, restart actions for the systemd service."""
    command = ['sudo', 'systemctl', action, 'tunnel-manager-web.service']
    print(f"Executing: {' '.join(command)}")
    result = os.system(' '.join(command))
    if result == 0:
        print(f"Service {action}ed successfully.")
    else:
        print(f"Error: Failed to {action} service. Check `systemctl status tunnel-manager-web.service` for details.")

def start_service(args):
    service_control('start')

def stop_service(args):
    service_control('stop')

def restart_service(args):
    service_control('restart')

def main():
    parser = argparse.ArgumentParser(
        description="A command-line interface to manage the Rathole Tunnel Manager."
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help='Available commands')

    # --- Password Command ---
    parser_password = subparsers.add_parser('password', help="Change a user's password.")
    parser_password.add_argument('username', type=str, help="The username to update.")
    parser_password.add_argument('new_password', type=str, help="The new password.")
    parser_password.set_defaults(func=change_password)

    # --- Reset Domain Command ---
    parser_reset_domain = subparsers.add_parser('reset-domain', help="Reset (delete) the configured domain name.")
    parser_reset_domain.set_defaults(func=reset_domain)

    # --- Service Control Commands ---
    parser_start = subparsers.add_parser('start', help="Start the web panel service.")
    parser_start.set_defaults(func=start_service)

    parser_stop = subparsers.add_parser('stop', help="Stop the web panel service.")
    parser_stop.set_defaults(func=stop_service)

    parser_restart = subparsers.add_parser('restart', help="Restart the web panel service.")
    parser_restart.set_defaults(func=restart_service)

    # If no command is provided, print help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    args.func(args)

if __name__ == '__main__':
    # This check prevents running the CLI logic if it's imported elsewhere.
    main()
