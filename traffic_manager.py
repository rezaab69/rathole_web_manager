import threading
import time
import iptables_manager
import database
import rathole_manager

def update_traffic_data_job():
    """
    This function is intended to be run in a background thread.
    It periodically fetches traffic stats, aggregates them with stored data,
    updates the database, and resets the iptables counters.
    """
    while True:
        try:
            # Get current traffic stats from iptables
            current_stats = iptables_manager.get_traffic_stats()

            if not current_stats:
                time.sleep(10)
                continue

            for service_name, stats in current_stats.items():
                # Get the last saved traffic data from the database
                saved_data = database.get_traffic_data(service_name) or {'sent_bytes': 0, 'recv_bytes': 0}

                # Calculate the new total
                total_sent = saved_data['sent_bytes'] + stats['sent']
                total_recv = saved_data['recv_bytes'] + stats['recv']

                # Update the database with the new totals
                database.update_traffic_data(service_name, total_sent, total_recv)

            # After processing all services, reset the iptables counters
            for service_name in current_stats.keys():
                iptables_manager.reset_traffic_counters(service_name)

        except Exception as e:
            print(f"Error in traffic update thread: {e}")
            # Avoid rapid-fire loops on critical error
            time.sleep(60)

        # Wait for 10 seconds before the next update
        time.sleep(10)

def start_traffic_updater():
    """Starts the background thread for updating traffic data."""
    traffic_thread = threading.Thread(target=update_traffic_data_job, daemon=True)
    traffic_thread.start()
    print("--- Traffic data updater thread started ---")
