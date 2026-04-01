import sqlite3
import hashlib
import time
from datetime import datetime, timedelta

# ---------------- DATABASE ----------------
conn = sqlite3.connect("secure_system.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT,
    failed_attempts INTEGER,
    locked INTEGER,
    lock_time TEXT,
    created TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    action TEXT,
    timestamp TEXT,
    risk TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS actions (
    username TEXT,
    action TEXT,
    timestamp TEXT
)
""")

conn.commit()

current_user = None

# ---------------- SECURITY ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def validate_password(password):
    return (
        len(password) >= 6 and
        any(c.isalpha() for c in password) and
        any(c.isdigit() for c in password)
    )

def analyze_activity(username, action):
    cursor.execute("SELECT action, timestamp FROM actions WHERE username=?", (username,))
    rows = cursor.fetchall()

    now = datetime.now()
    recent_actions = 0
    transfers = 0

    for act, ts in rows:
        ts = datetime.fromisoformat(ts)
        if (now - ts).seconds < 60:  # last 1 minute
            recent_actions += 1
        if act == "transfer":
            transfers += 1

    # Risk logic
    if recent_actions > 5:
        return "High Risk"
    if transfers > 3:
        return "High Risk"
    if len(rows) > 10:
        return "Medium Risk"
    return "Normal"

# ---------------- HELPERS ----------------
def log_action(username, action, risk):
    cursor.execute("INSERT INTO logs (username, action, timestamp, risk) VALUES (?, ?, ?, ?)",
                   (username, action, datetime.now().isoformat(), risk))

def check_unlock(user):
    if user[3] == 1 and user[4]:
        lock_time = datetime.fromisoformat(user[4])
        if datetime.now() - lock_time > timedelta(minutes=1):
            cursor.execute("UPDATE users SET locked=0, failed_attempts=0 WHERE username=?", (user[0],))
            conn.commit()
            return True
    return False

# ---------------- FEATURES ----------------
def register():
    username = input("Username: ").strip()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    if cursor.fetchone():
        print("User already exists.")
        return

    password = input("Password: ").strip()

    if not validate_password(password):
        print("Weak password.")
        return

    cursor.execute("INSERT INTO users VALUES (?, ?, 0, 0, NULL, ?)",
                   (username, hash_password(password), datetime.now().isoformat()))
    conn.commit()

    print("✅ Account created!")

def login():
    global current_user

    username = input("Username: ").strip()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()

    if not user:
        print("User not found.")
        return

    if user[3] == 1:
        if check_unlock(user):
            print("🔓 Account auto-unlocked. Try again.")
        else:
            print("🚫 Account locked. Try later.")
            return

    password = input("Password: ").strip()

    if hash_password(password) == user[1]:
        current_user = username
        cursor.execute("UPDATE users SET failed_attempts=0 WHERE username=?", (username,))
        conn.commit()

        log_action(username, "login", "Normal")
        print(f"✅ Welcome {username}")
    else:
        attempts = user[2] + 1

        if attempts >= 3:
            cursor.execute("""
            UPDATE users 
            SET failed_attempts=?, locked=1, lock_time=? 
            WHERE username=?
            """, (attempts, datetime.now().isoformat(), username))
            print("🚫 Account locked!")
        else:
            cursor.execute("UPDATE users SET failed_attempts=? WHERE username=?", (attempts, username))
            print("❌ Wrong password")

        conn.commit()

def perform_action():
    global current_user

    if not current_user:
        print("Login first.")
        return

    print("\n1. View Balance\n2. Transfer\n3. Logout")
    choice = input("Choose: ")

    if choice == '1':
        action = "view_balance"
    elif choice == '2':
        action = "transfer"
    elif choice == '3':
        current_user = None
        print("Logged out.")
        return
    else:
        print("Invalid")
        return

    risk = analyze_activity(current_user, action)

    cursor.execute("INSERT INTO actions VALUES (?, ?, ?)",
                   (current_user, action, datetime.now().isoformat()))

    if risk == "High Risk":
        cursor.execute("""
        UPDATE users SET locked=1, lock_time=? WHERE username=?
        """, (datetime.now().isoformat(), current_user))
        print("🚫 Suspicious activity detected! Account locked.")

    log_action(current_user, action, risk)
    conn.commit()

    print(f"Action: {action} | Risk: {risk}")

def view_logs():
    if not current_user:
        print("Login first.")
        return

    cursor.execute("SELECT action, timestamp, risk FROM logs WHERE username=?", (current_user,))
    for row in cursor.fetchall():
        print(f"{row[1]} | {row[0]} | {row[2]}")

def reset_password():
    username = input("Username: ")

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    if not cursor.fetchone():
        print("User not found.")
        return

    new_pass = input("New password: ")

    if not validate_password(new_pass):
        print("Weak password.")
        return

    cursor.execute("""
    UPDATE users 
    SET password=?, locked=0, failed_attempts=0 
    WHERE username=?
    """, (hash_password(new_pass), username))

    conn.commit()
    print("✅ Password reset done")

# ---------------- MENU ----------------
def menu():
    while True:
        print("\n=== 🔐 Advanced Security System ===")
        print("1. Register")
        print("2. Login")
        print("3. Perform Action")
        print("4. View Logs")
        print("5. Reset Password")
        print("6. Exit")

        choice = input("Select: ")

        if choice == '1':
            register()
        elif choice == '2':
            login()
        elif choice == '3':
            perform_action()
        elif choice == '4':
            view_logs()
        elif choice == '5':
            reset_password()
        elif choice == '6':
            print("Bye!")
            break
        else:
            print("Invalid")

# ---------------- RUN ----------------
if __name__ == "__main__":
    menu()