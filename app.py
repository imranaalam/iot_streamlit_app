import streamlit as st
import sqlite3
from datetime import datetime
import pandas as pd
import hashlib
import uuid

# -----------------------------
# Configuration
# -----------------------------

# Database file path
DB_FILE = "database/iot_app.db"

# -----------------------------
# Database Functions
# -----------------------------

def init_db():
    """Initialize the SQLite database and create necessary tables."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Create users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    # Create devices table
    c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'offline',
            last_seen TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    # Create sensor_data table
    c.execute("""
        CREATE TABLE IF NOT EXISTS sensor_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            temperature REAL,
            humidity REAL,
            timestamp TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (device_id)
        )
    """)
    # Create commands table
    c.execute("""
        CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            command TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            timestamp TEXT,
            FOREIGN KEY (device_id) REFERENCES devices (device_id)
        )
    """)
    conn.commit()
    conn.close()

def hash_password(password):
    """Hash a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hashed):
    """Verify a stored password against one provided by user."""
    return hash_password(password) == hashed

def register_user(username, password):
    """Register a new user."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        password_hash = hash_password(password)
        c.execute("""
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
        """, (username, password_hash))
        conn.commit()
        success = True
        message = "User registered successfully."
    except sqlite3.IntegrityError:
        success = False
        message = "Username already exists."
    conn.close()
    return success, message

def login_user(username, password):
    """Login user and return user id if successful."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    if user and verify_password(password, user[1]):
        return user[0]
    else:
        return None

def register_device(user_id, device_id, name):
    """Register a new device for a user."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    token = str(uuid.uuid4())
    try:
        c.execute("""
            INSERT INTO devices (user_id, device_id, name, token, status, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, device_id, name, token, 'offline', None))
        conn.commit()
        success = True
        message = "Device registered successfully."
    except sqlite3.IntegrityError:
        success = False
        message = "Device ID or Token already exists."
    conn.close()
    return success, message, token

def update_sensor_data(device_id, temperature, humidity):
    """Update sensor data for a device."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Check if device exists
    c.execute('SELECT user_id FROM devices WHERE device_id = ?', (device_id,))
    device = c.fetchone()
    if not device:
        conn.close()
        return False, "Device not registered."
    # Insert sensor data
    timestamp = datetime.utcnow().isoformat()
    c.execute("""
        INSERT INTO sensor_data (device_id, temperature, humidity, timestamp)
        VALUES (?, ?, ?, ?)
    """, (device_id, temperature, humidity, timestamp))
    # Update device status and last_seen
    c.execute("""
        UPDATE devices
        SET status = ?, last_seen = ?
        WHERE device_id = ?
    """, ('online', timestamp, device_id))
    conn.commit()
    conn.close()
    return True, "Sensor data updated successfully."

def add_command(device_id, command):
    """Add a new command for a device."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    timestamp = datetime.utcnow().isoformat()
    try:
        c.execute("""
            INSERT INTO commands (device_id, command, status, timestamp)
            VALUES (?, ?, ?, ?)
        """, (device_id, command, 'pending', timestamp))
        conn.commit()
        success = True
        message = "Command added successfully."
    except sqlite3.IntegrityError:
        success = False
        message = "Failed to add command."
    conn.close()
    return success, message

def get_user_devices(user_id):
    """Retrieve all devices for a user."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT device_id, name, status, last_seen, token
        FROM devices
        WHERE user_id = ?
    """, (user_id,))
    devices = c.fetchall()
    conn.close()
    return devices

def get_latest_sensor_data(device_id):
    """Retrieve the latest sensor data for a specific device."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT temperature, humidity, timestamp
        FROM sensor_data
        WHERE device_id = ?
        ORDER BY timestamp DESC
        LIMIT 1
    """, (device_id,))
    data = c.fetchone()
    conn.close()
    return data

def get_all_sensor_data(device_id):
    """Retrieve all sensor data for a specific device."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT temperature, humidity, timestamp
        FROM sensor_data
        WHERE device_id = ?
        ORDER BY timestamp DESC
    """, (device_id,))
    data = c.fetchall()
    conn.close()
    return data

def get_pending_commands(device_id):
    """Retrieve pending commands for a device."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        SELECT id, command, timestamp
        FROM commands
        WHERE device_id = ? AND status = 'pending'
        ORDER BY timestamp ASC
    """, (device_id,))
    commands = c.fetchall()
    conn.close()
    return commands

def update_command_status(command_id, status):
    """Update the status of a command."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
        UPDATE commands
        SET status = ?
        WHERE id = ?
    """, (status, command_id))
    conn.commit()
    conn.close()
    return True

# -----------------------------
# Initialize Database
# -----------------------------

init_db()

# -----------------------------
# Streamlit App
# -----------------------------

def main():
    st.set_page_config(page_title="IoT Dashboard", layout="wide")
    st.title("📱 IoT Dashboard")

    # Initialize session state
    if 'user_id' not in st.session_state:
        st.session_state['user_id'] = None
        st.session_state['username'] = ""

    # Sidebar Navigation
    # Modified to always include "My Devices" for testing
    if st.session_state['user_id']:
        menu = ["Home", "My Devices", "Logout"]
    else:
        menu = ["Home", "My Devices", "Login", "Register"]  # "My Devices" is always present
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Home":
        st.subheader("Welcome to the IoT Dashboard")
        st.markdown("""
            This application allows you to monitor and manage your IoT devices.
            - **Register** to create an account.
            - **Login** to access your dashboard.
            - **Register Devices** to add your IoT devices.
            - **View Sensor Data** from your devices in real-time.
            - **Send Commands** to your devices.
        """)

    elif choice == "Login":
        if st.session_state['user_id']:
            st.warning("You are already logged in.")
        else:
            st.subheader("Login")

            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type='password')
                submit = st.form_submit_button("Login")

            if submit:
                user_id = login_user(username, password)
                if user_id:
                    st.session_state['user_id'] = user_id
                    st.session_state['username'] = username
                    st.success(f"Logged in as {username}")
                else:
                    st.error("Invalid username or password.")

    elif choice == "Register":
        if st.session_state['user_id']:
            st.warning("You are already logged in.")
        else:
            st.subheader("Register")

            with st.form("register_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type='password')
                confirm_password = st.text_input("Confirm Password", type='password')
                submit = st.form_submit_button("Register")

            if submit:
                if password != confirm_password:
                    st.error("Passwords do not match.")
                elif len(password) < 6:
                    st.error("Password must be at least 6 characters.")
                else:
                    success, message = register_user(username, password)
                    if success:
                        st.success(message)
                        st.info("Please login to continue.")
                    else:
                        st.error(message)

    elif choice == "My Devices":
        if not st.session_state['user_id']:
            st.warning("Please login to access the 'My Devices' page.")
            return  # Exit the function early to prevent further execution
        else:
            st.subheader("My Devices")

            # Register New Device
            with st.expander("Register New Device"):
                with st.form("device_registration_form"):
                    device_id = st.text_input("Device ID")
                    device_name = st.text_input("Device Name")
                    submit_device = st.form_submit_button("Register Device")

                if submit_device:
                    if device_id and device_name:
                        success, message, token = register_device(st.session_state['user_id'], device_id, device_name)
                        if success:
                            st.success(message)
                            st.info(f"Device Token (Keep it secret!): {token}")
                        else:
                            st.error(message)
                    else:
                        st.error("Please provide both Device ID and Name.")

            # Display Devices
            devices = get_user_devices(st.session_state['user_id'])
            if devices:
                devices_df = pd.DataFrame(devices, columns=["Device ID", "Name", "Status", "Last Seen", "Token"])
                st.dataframe(devices_df)
            else:
                st.info("No devices registered yet.")

            # Display Sensor Data for Selected Device
            st.subheader("Latest Sensor Data")
            device_ids = [device[0] for device in devices]
            selected_device = st.selectbox("Select Device", device_ids if device_ids else ["No devices available"])

            if selected_device and selected_device != "No devices available":
                data = get_latest_sensor_data(selected_device)
                if data:
                    temperature, humidity, timestamp = data
                    st.write(f"**Device ID:** {selected_device}")
                    st.write(f"**Temperature:** {temperature} °C")
                    st.write(f"**Humidity:** {humidity} %")
                    st.write(f"**Timestamp:** {timestamp}")
                else:
                    st.write("No sensor data available for this device.")

                st.subheader("All Sensor Data")
                all_data = get_all_sensor_data(selected_device)
                if all_data:
                    sensor_df = pd.DataFrame(all_data, columns=["Temperature (°C)", "Humidity (%)", "Timestamp"])
                    st.dataframe(sensor_df)
                else:
                    st.write("No sensor data available.")

            # Send Commands to Device
            st.subheader("Send Command to Device")
            with st.form("command_form"):
                command = st.text_input("Enter Command")
                submit_command = st.form_submit_button("Send Command")

            if submit_command:
                if selected_device and selected_device != "No devices available":
                    if command:
                        success, message = add_command(selected_device, command)
                        if success:
                            st.success(message)
                        else:
                            st.error(message)
                    else:
                        st.error("Please enter a command.")
                else:
                    st.error("Please select a valid device.")

    elif choice == "Logout":
        if st.session_state['user_id']:
            st.session_state['user_id'] = None
            st.session_state['username'] = ""
            st.success("Logged out successfully.")
        else:
            st.warning("You are not logged in.")

    # -----------------------------
    # Handle Incoming Device Data and Commands
    # -----------------------------

    # Retrieve query parameters
    query_params = st.experimental_get_query_params()

    # Debugging: Display query parameters
    # Uncomment the next line to see the query parameters in the app
    # st.write("Query Parameters:", query_params)

    # Device Sending Sensor Data
    if all(k in query_params for k in ['token', 'device_id', 'temperature', 'humidity']):
        token = query_params.get('token')[0]
        device_id = query_params.get('device_id')[0]
        temperature = query_params.get('temperature')[0]
        humidity = query_params.get('humidity')[0]

        # Validate data
        try:
            temperature = float(temperature)
            humidity = float(humidity)
        except ValueError:
            st.error("Invalid temperature or humidity value.")
        else:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('SELECT user_id FROM devices WHERE token = ? AND device_id = ?', (token, device_id))
            device = c.fetchone()
            conn.close()
            if device:
                success, message = update_sensor_data(device_id, temperature, humidity)
                if success:
                    st.success("Sensor data received successfully.")
                else:
                    st.error(message)
            else:
                st.error("Invalid token or device ID.")

    # Device Fetching Commands
    elif all(k in query_params for k in ['token', 'device_id', 'get_commands']):
        token = query_params.get('token')[0]
        device_id = query_params.get('device_id')[0]

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT user_id FROM devices WHERE token = ? AND device_id = ?', (token, device_id))
        device = c.fetchone()
        conn.close()
        if device:
            commands = get_pending_commands(device_id)
            if commands:
                commands_list = [{"id": cmd[0], "command": cmd[1], "timestamp": cmd[2]} for cmd in commands]
                st.json(commands_list)
            else:
                st.json([])
        else:
            st.error("Invalid token or device ID.")

    # Device Updating Command Status
    elif all(k in query_params for k in ['token', 'device_id', 'command_id', 'status']):
        token = query_params.get('token')[0]
        device_id = query_params.get('device_id')[0]
        command_id = query_params.get('command_id')[0]
        status = query_params.get('status')[0]

        if status not in ['executed', 'failed']:
            st.error("Invalid status value.")
        else:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('SELECT user_id FROM devices WHERE token = ? AND device_id = ?', (token, device_id))
            device = c.fetchone()
            conn.close()
            if device:
                success = update_command_status(command_id, status)
                if success:
                    st.success("Command status updated successfully.")
                else:
                    st.error("Failed to update command status.")
            else:
                st.error("Invalid token or device ID.")

if __name__ == "__main__":
    main()
