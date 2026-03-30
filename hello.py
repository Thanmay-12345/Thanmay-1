import json
from file_handler import load_users, save_users, load_logs, save_logs
from detector import analyze_activity, check_account_status
from utils import validate_password, hash_password, verify_password
from datetime import datetime


current_user = None
users = load_users()
logs = load_logs()

def login():
    global current_user, users, logs
    username = input("\nEnter username: ").strip()
    
    if username not in users:
        create = input("Account not found. Create new? (y/n): ").lower()
        if create == 'y':
            password = input("Enter password: ").strip()
            if not validate_password(password):
                print("Password must be 6+ chars, contain letters and numbers.")
                return
            users[username] = {
                "password": hash_password(password),
                "failed_attempts": 0,
                "locked": False,
                "actions": [],
                "created": datetime.now().isoformat()
            }
            save_users(users)
            print("Account created successfully!")
        return
    
    user = users[username]
    if user["locked"]:
        reset = input("Account locked. Reset password? (y/n): ").lower()
        if reset == 'y':
            forgot_password()
        return
    
    password = input("Enter password: ").strip()
    if verify_password(password, user["password"]):
        current_user = username
        user["failed_attempts"] = 0
        save_users(users)
        logs.append({"user": username, "action": "login", "timestamp": datetime.now().isoformat(), "risk": "Normal"})
        save_logs(logs)
        print(f"Welcome, {username}!")
    else:
        user["failed_attempts"] += 1
        if user["failed_attempts"] >= 3:
            user["locked"] = True
            print("Account locked due to failed attempts.")
        save_users(users)
        print("Invalid password.")

def perform_action():
    global current_user, users, logs
    if not current_user:
        print("Please login first.")
        return
    
    print("\n1. View Balance\n2. Transfer Money\n3. Logout")
    choice = input("Select action: ").strip()
    
    if choice == '1':
        action = "view_balance"
    elif choice == '2':
        action = "transfer"
    elif choice == '3':
        current_user = None
        print("Logged out.")
        return
    else:
        print("Invalid choice.")
        return
    
    risk = analyze_activity(users[current_user]["actions"], action)
    users[current_user]["actions"].append(action)
    
    if risk == "High Risk":
        users[current_user]["locked"] = True
        print("Account locked due to suspicious activity!")
    
    logs.append({"user": current_user, "action": action, "timestamp": datetime.now().isoformat(), "risk": risk})
    save_users(users)
    save_logs(logs)
    print(f"Action: {action} | Risk Level: {risk}")

def view_logs():
    if not current_user:
        print("Please login first.")
        return
    user_logs = [l for l in logs if l["user"] == current_user]
    for log in user_logs:
        print(f"{log['timestamp']} | {log['action']} | {log['risk']}")

def forgot_password():
    username = input("Enter username: ").strip()
    if username not in users:
        print("User not found.")
        return
    new_password = input("Enter new password: ").strip()
    if not validate_password(new_password):
        print("Password must be 6+ chars, contain letters and numbers.")
        return
    users[username]["password"] = hash_password(new_password)
    users[username]["locked"] = False
    users[username]["failed_attempts"] = 0
    users[username]["actions"] = []
    save_users(users)
    print("Password reset successfully!")

def menu():
    while True:
        print("\n=== Suspicious Activity Detector ===")
        print("1. Login\n2. Perform Action\n3. View Logs\n4. Forgot Password\n5. Exit")
        choice = input("Select: ").strip()
        
        if choice == '1':
            login()
        elif choice == '2':
            perform_action()
        elif choice == '3':
            view_logs()
        elif choice == '4':
            forgot_password()
        elif choice == '5':
            print("Goodbye!")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    menu()