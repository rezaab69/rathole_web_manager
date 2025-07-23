import sqlite3
import bcrypt
import os

DATABASE_DIR = os.path.join(os.path.dirname(__file__), 'instance')
DATABASE_PATH = os.path.join(DATABASE_DIR, 'users.db')

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    os.makedirs(DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database and creates tables if they don't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    ''')

    # Settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')

    # Traffic data table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS traffic_data (
            service_name TEXT PRIMARY KEY,
            sent_bytes INTEGER NOT NULL,
            recv_bytes INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

def add_user(username, password):
    """Adds a new user to the database with a hashed password."""
    if get_user(username):
        return False # User already exists

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed_password.decode('utf-8')))
        conn.commit()
        return True
    except sqlite3.IntegrityError: # Should be caught by get_user check, but as a safeguard
        return False
    finally:
        conn.close()

def verify_user(username, password):
    """Verifies a user's credentials against the stored hash."""
    user = get_user(username)
    if user:
        password_hash = user['password_hash'].encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), password_hash):
            return True
    return False

def get_user(username):
    """Retrieves a user by username."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def update_password(username, new_password):
    """Updates a user's password."""
    user = get_user(username)
    if not user:
        return False # User not found

    new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (new_hashed_password.decode('utf-8'), username))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating password: {e}") # For logging
        return False
    finally:
        conn.close()

def get_setting(key, default=None):
    """Retrieves a setting value by key."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row['value'] if row else default

def set_setting(key, value):
    """Saves or updates a setting."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Use INSERT OR REPLACE to handle both new and existing keys
        cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, value))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error setting '{key}': {e}")
        return False
    finally:
        conn.close()

def delete_setting(key):
    """Deletes a setting by key."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM settings WHERE key = ?", (key,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting setting '{key}': {e}")
        return False
    finally:
        conn.close()

def update_traffic_data(service_name, sent_bytes, recv_bytes):
    """Inserts or updates the traffic data for a given service."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO traffic_data (service_name, sent_bytes, recv_bytes, timestamp)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(service_name) DO UPDATE SET
                sent_bytes = excluded.sent_bytes,
                recv_bytes = excluded.recv_bytes,
                timestamp = CURRENT_TIMESTAMP
        """, (service_name, sent_bytes, recv_bytes))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating traffic data for '{service_name}': {e}")
        return False
    finally:
        conn.close()

def get_traffic_data(service_name):
    """Retrieves the last recorded traffic data for a given service."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT sent_bytes, recv_bytes FROM traffic_data WHERE service_name = ?", (service_name,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {'sent_bytes': row['sent_bytes'], 'recv_bytes': row['recv_bytes']}
    return None

def delete_traffic_data(service_name):
    """Deletes the traffic data for a given service."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM traffic_data WHERE service_name = ?", (service_name,))
        conn.commit()
        return True
    except Exception as e:
        print(f"Error deleting traffic data for '{service_name}': {e}")
        return False
    finally:
        conn.close()

if __name__ == '__main__':
    # For testing and initial setup
    print("Initializing database...")
    init_db()
    print("Database initialized.")
