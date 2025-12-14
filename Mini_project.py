import tkinter as tk
from tkinter import messagebox, ttk
import os
import json
import hashlib
import secrets
from cryptography.fernet import Fernet

class SecureLoginApp:
 def __init__(self,root):
    self.root = root
    self.root.title("Secure Login System")
    self.root.geometry("420x520")
    self.root.resizable(False, False)
    self.current_user = None

    self.setup_encryption()

    self.notebook = ttk.Notebook(root)
    self.notebook.pack(fill="both", expand=True, padx=20, pady=20)

    self.create_register_tab()
    self.create_login_tab()

 def setup_encryption(self):
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as f:
            f.write(key)
    else:
        with open("key.key", "rb") as f:
            key = f.read()

    self.fernet = Fernet(key)

    if not os.path.exists("credentials.enc"):
        data = {"users": []}
        encrypted = self.fernet.encrypt(json.dumps(data).encode())
        with open("credentials.enc", "wb") as f:
            f.write(encrypted)

 def load_credentials(self):
    with open("credentials.enc", "rb") as f:
        encrypted_data = f.read()
    decrypted = self.fernet.decrypt(encrypted_data).decode()
    return json.loads(decrypted)

 def save_credentials(self, data):
    encrypted = self.fernet.encrypt(json.dumps(data, indent=2).encode())
    with open("credentials.enc", "wb") as f:
        f.write(encrypted)

 def create_register_tab(self):
    frame = ttk.Frame(self.notebook)
    self.notebook.add(frame, text="Register")

    ttk.Label(frame, text="Register New User",
              font=("Arial", 14, "bold")).pack(pady=20)

    ttk.Label(frame, text="Username:").pack()
    self.reg_username = ttk.Entry(frame, width=30)
    self.reg_username.pack(pady=5)

    ttk.Label(frame, text="Password:").pack()
    self.reg_password = ttk.Entry(frame, show="*", width=30)
    self.reg_password.pack(pady=5)

    ttk.Label(frame, text="Role:").pack()
    self.reg_role = ttk.Combobox(frame, values=["user", "admin"], width=27)
    self.reg_role.pack(pady=5)

    ttk.Button(frame, text="Register",
               command=self.register_user).pack(pady=20)

 def register_user(self):
    username = self.reg_username.get().strip()
    password = self.reg_password.get()
    role = self.reg_role.get().strip().lower()

    if not username or not password or not role:
        messagebox.showerror("Error", "Please fill all fields.")
        return

    if role not in ["user", "admin"]:
        messagebox.showerror("Error", "Role must be 'user' or 'admin'.")
        return

    data = self.load_credentials()

    if role == "admin" and any(u["role"] == "admin" for u in data["users"]):
        messagebox.showerror("Error", "An admin already exists. Only one admin is allowed.")
        return

    if any(u["username"] == username for u in data["users"]):
        messagebox.showerror("Error", "Username already exists.")
        return

    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()

    user_data = {
        "id": secrets.token_hex(8),
        "username": username,
        "password_hash": password_hash,
        "salt": salt,
        "role": role
    }

    data["users"].append(user_data)
    self.save_credentials(data)

    messagebox.showinfo("Success", f"User '{username}' registered as {role}.")
    self.clear_register_fields()

 def clear_register_fields(self):
    self.reg_username.delete(0, tk.END)
    self.reg_password.delete(0, tk.END)
    self.reg_role.set("")

 def create_login_tab(self):
    frame = ttk.Frame(self.notebook)
    self.notebook.add(frame, text="Login")

    ttk.Label(frame, text="Login",
              font=("Arial", 14, "bold")).pack(pady=20)

    ttk.Label(frame, text="Username:").pack()
    self.login_username = ttk.Entry(frame, width=30)
    self.login_username.pack(pady=5)

    ttk.Label(frame, text="Password:").pack()
    self.login_password = ttk.Entry(frame, show="*", width=30)
    self.login_password.pack(pady=5)

    ttk.Button(frame, text="Login",
               command=self.login_user).pack(pady=20)

 def login_user(self):
    username = self.login_username.get().strip()
    password = self.login_password.get()

    if not username or not password:
        messagebox.showerror("Error", "Please enter username and password.")
        return

    data = self.load_credentials()
    user = next((u for u in data["users"] if u["username"] == username), None)

    if not user:
        messagebox.showerror("Error", "User not found.")
        return

    check_hash = hashlib.sha256((password + user["salt"]).encode()).hexdigest()
    if check_hash != user["password_hash"]:
        messagebox.showerror("Error", "Incorrect password.")
        self.login_password.delete(0, tk.END)
        return

    self.current_user = user
    messagebox.showinfo("Success", f"Welcome, {user['username']} ({user['role']}).")
    self.show_dashboard()

 def show_dashboard(self):
    self.notebook.pack_forget()

    self.dashboard_frame = ttk.Frame(self.root)
    self.dashboard_frame.pack(fill="both", expand=True, padx=20, pady=20)

    ttk.Label(self.dashboard_frame,
              text=f"Dashboard - {self.current_user['username']}",
              font=("Arial", 14, "bold")).pack(pady=10)

    ttk.Label(self.dashboard_frame,
              text=f"Role: {self.current_user['role']}").pack(pady=5)

    ttk.Button(self.dashboard_frame,
               text="Change Password",
               command=self.open_change_password_window).pack(pady=10)

    if self.current_user["role"] == "admin":
        ttk.Button(self.dashboard_frame,
                   text="View All Users",
                   command=self.admin_panel).pack(pady=10)

    ttk.Button(self.dashboard_frame,
               text="Logout",
               command=self.logout).pack(pady=10)

 def open_change_password_window(self):
    win = tk.Toplevel(self.root)
    win.title("Change Password")
    win.geometry("350x260")
    win.resizable(False, False)

    ttk.Label(win, text="Current Password:").pack(pady=5)
    cur_pass_entry = ttk.Entry(win, show="*")
    cur_pass_entry.pack(pady=5)

    ttk.Label(win, text="New Password:").pack(pady=5)
    new_pass_entry = ttk.Entry(win, show="*")
    new_pass_entry.pack(pady=5)

    ttk.Label(win, text="Confirm New Password:").pack(pady=5)
    confirm_pass_entry = ttk.Entry(win, show="*")
    confirm_pass_entry.pack(pady=5)

    def apply_change():
        cur = cur_pass_entry.get()
        new = new_pass_entry.get()
        confirm = confirm_pass_entry.get()

        if not cur or not new or not confirm:
            messagebox.showerror("Error", "Please fill all fields.")
            return

        if new != confirm:
            messagebox.showerror("Error", "New passwords do not match.")
            return

        data = self.load_credentials()
        user = next((u for u in data["users"]
                     if u["username"] == self.current_user["username"]), None)

        if not user:
            messagebox.showerror("Error", "User not found in storage.")
            return

        cur_hash = hashlib.sha256((cur + user["salt"]).encode()).hexdigest()
        if cur_hash != user["password_hash"]:
            messagebox.showerror("Error", "Current password is incorrect.")
            return

        new_salt = secrets.token_hex(16)
        new_hash = hashlib.sha256((new + new_salt).encode()).hexdigest()
        user["salt"] = new_salt
        user["password_hash"] = new_hash

        self.save_credentials(data)
        messagebox.showinfo("Success", "Password changed successfully.")
        win.destroy()

    ttk.Button(win, text="Change Password",
               command=apply_change).pack(pady=15)

 def admin_panel(self):
    data = self.load_credentials()

    admin_window = tk.Toplevel(self.root)
    admin_window.title("Admin Panel - All Users")
    admin_window.geometry("550x380")

    ttk.Label(admin_window, text="All Users",
              font=("Arial", 14, "bold")).pack(pady=10)

    columns = ("ID", "Username", "Role", "Hash")
    self.user_tree = ttk.Treeview(admin_window, columns=columns, show="headings")
    for col in columns:
        self.user_tree.heading(col, text=col)

    self.user_tree.column("ID", width=80)
    self.user_tree.column("Username", width=120)
    self.user_tree.column("Role", width=80)
    self.user_tree.column("Hash", width=230)

    for user in data["users"]:
        self.user_tree.insert(
            "",
            "end",
            values=(
                user["id"],
                user["username"],
                user["role"],
                user["password_hash"][:18] + "..."
            )
        )

    self.user_tree.pack(fill="both", expand=True, padx=10, pady=10)

    ttk.Button(admin_window,
               text="Delete Selected User",
               command=self.delete_selected_user).pack(pady=5)

 def delete_selected_user(self):
    selected = self.user_tree.selection()
    if not selected:
        messagebox.showerror("Error", "No user selected.")
        return
    item_id = selected[0]
    values = self.user_tree.item(selected, "values")
    user_id = values[0]
    username = values[1]

    if username == self.current_user["username"]:
        messagebox.showerror("Error", "You cannot delete your own account.")
        return

    confirm = messagebox.askyesno("Confirm",
                                  f"Delete user '{username}'?")
    if not confirm:
        return

    data = self.load_credentials()
    new_users = [u for u in data["users"] if u["id"] != user_id]
    if len(new_users) == len(data["users"]):
        messagebox.showerror("Error", "User not found in storage.")
        return

    data["users"] = new_users
    self.save_credentials(data)

    self.user_tree.delete(selected)
    messagebox.showinfo("Success", f"User '{username}' deleted.")

 def logout(self):
    self.current_user = None
    if hasattr(self, "dashboard_frame"):
        self.dashboard_frame.destroy()
    self.notebook.pack(fill="both", expand=True, padx=20, pady=20)
    self.login_username.delete(0, tk.END)
    self.login_password.delete(0, tk.END)
    self.login_username.focus_set()

if __name__== "__main__":
  root = tk.Tk()
  app = SecureLoginApp(root)
  root.mainloop() 