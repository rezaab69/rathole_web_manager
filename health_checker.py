import time
import threading
import rathole_manager

def check_and_restart_instances():
    """
    Periodically checks all instances and restarts them if they are marked for
    auto-restart and are not currently running.
    """
    print("Health checker thread started.")
    while True:
        try:
            print("Health checker: Running check...")

            for instance_type in ['server', 'client']:
                instances = rathole_manager.get_all_instances(instance_type)
                for name, details in instances.items():
                    # The get_all_instances function now returns the real-time status
                    if details.get('auto_restart') and details.get('status') == 'stopped':
                        print(f"Health checker: Instance '{name}' is stopped and has auto-restart enabled. Restarting...")
                        rathole_manager.start_instance(instance_type, name)

        except Exception as e:
            print(f"Health checker: Encountered an error: {e}")

        # Wait for 60 seconds before the next check
        time.sleep(60)

def start_background_checker():
    """
    Starts the health checker in a separate, daemonized thread.
    """
    checker_thread = threading.Thread(target=check_and_restart_instances, daemon=True)
    checker_thread.start()
    return checker_thread
