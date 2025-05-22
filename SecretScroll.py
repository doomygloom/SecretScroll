#!/usr/bin/env python3
import os
import json
import time
import base64
import getpass
import platform
import subprocess
import secrets
from threading import Thread
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm

DATA_FILE = os.path.expanduser("~/.secret_scroll")
BACKUP_FILE = os.path.expanduser("~/.secret_scroll_backup")
LOCK_TIMEOUT = 300
CLIPBOARD_TIMEOUT = 30
KDF_ITERATIONS = 600_000

console = Console()

def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

def generate_salt() -> bytes:
    """
    Produce a 16-byte salt whose first byte's MSB is guaranteed 0,
    so we can use that bit as a flag in stored_salt.
    """
    raw = secrets.token_bytes(16)
    first = raw[0] & 0x7F
    return bytes([first]) + raw[1:]

def get_yubikey_response(passphrase: str) -> bytes:
    # 32-byte SHA256 challenge
    challenge = hashlib.sha256(passphrase.encode()).digest()
    try:
        result = subprocess.run(
            ['ykman', 'otp', 'calculate', '2', challenge.hex()],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True
        )
        resp_hex = result.stdout.strip().decode()
        return bytes.fromhex(resp_hex)
    except subprocess.CalledProcessError as e:
        console.print("[bold red]YubiKey challenge failed.")
        if e.stderr:
            console.print(f"[dim]{e.stderr.decode().strip()}")
        exit(1)

def derive_key(passphrase: str, salt: bytes, use_yubi: bool) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
        backend=default_backend()
    )
    base_key = kdf.derive(passphrase.encode())
    if use_yubi:
        yubi_resp = get_yubikey_response(passphrase)
        combined = hmac.new(yubi_resp, base_key, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(combined)
    else:
        return base64.urlsafe_b64encode(base_key)

def get_fernet(passphrase: str, salt: bytes, use_yubi: bool) -> Fernet:
    return Fernet(derive_key(passphrase, salt, use_yubi))

def generate_hmac(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def write_secure_file(path: str, content: bytes):
    with open(path, 'wb') as f:
        f.write(content)
    os.chmod(path, 0o600)

def save_data(data, fernet: Fernet, salt: bytes, passphrase: str, use_yubi: bool):
    encrypted = fernet.encrypt(json.dumps(data).encode())
    mac_key = derive_key(passphrase, salt, use_yubi)
    mac = generate_hmac(base64.urlsafe_b64decode(mac_key), encrypted)
    if use_yubi:
        stored_salt = bytes([salt[0] | 0x80]) + salt[1:]
    else:
        stored_salt = bytes([salt[0] & 0x7F]) + salt[1:]
    write_secure_file(DATA_FILE, stored_salt + encrypted + mac)

def backup_data(data, fernet: Fernet, salt: bytes, passphrase: str, use_yubi: bool):
    encrypted = fernet.encrypt(json.dumps(data).encode())
    mac_key = derive_key(passphrase, salt, use_yubi)
    mac = generate_hmac(base64.urlsafe_b64decode(mac_key), encrypted)
    if use_yubi:
        stored_salt = bytes([salt[0] | 0x80]) + salt[1:]
    else:
        stored_salt = bytes([salt[0] & 0x7F]) + salt[1:]
    write_secure_file(BACKUP_FILE, stored_salt + encrypted + mac)

def load_data_with_salt(passphrase: str, use_yubi: bool):
    if not os.path.exists(DATA_FILE):
        return [], generate_salt()

    raw = open(DATA_FILE, 'rb').read()
    if len(raw) < 16 + 32:
        console.print("[bold red]Corrupt data file.")
        exit(1)

    stored_salt = raw[:16]
    encrypted    = raw[16:-32]
    mac          = raw[-32:]

    yubi_required = bool(stored_salt[0] & 0x80)
    salt = bytes([stored_salt[0] & 0x7F]) + stored_salt[1:]

    if yubi_required and not use_yubi:
        console.print("[bold red]YubiKey authentication is required for this data.")
        exit(1)

    mac_key = derive_key(passphrase, salt, use_yubi)
    expected = generate_hmac(base64.urlsafe_b64decode(mac_key), encrypted)
    if not hmac.compare_digest(mac, expected):
        console.print("[bold red]Integrity check failed. Possible tampering detected.")
        exit(1)

    try:
        data = get_fernet(passphrase, salt, use_yubi).decrypt(encrypted)
        return json.loads(data), salt
    except InvalidToken:
        console.print("[bold red]Access denied.")
        exit(1)

def restore_backup(passphrase: str, use_yubi: bool):
    if not os.path.exists(BACKUP_FILE):
        return [], None

    raw = open(BACKUP_FILE, 'rb').read()
    if len(raw) < 16 + 32:
        console.print("[bold red]Corrupt backup file.")
        return [], None

    stored_salt = raw[:16]
    encrypted   = raw[16:-32]
    mac         = raw[-32:]

    yubi_required = bool(stored_salt[0] & 0x80)
    salt = bytes([stored_salt[0] & 0x7F]) + stored_salt[1:]

    if yubi_required and not use_yubi:
        console.print("[bold red]YubiKey is required to restore this backup.")
        return [], None

    mac_key = derive_key(passphrase, salt, use_yubi)
    expected = generate_hmac(base64.urlsafe_b64decode(mac_key), encrypted)
    if not hmac.compare_digest(mac, expected):
        console.print("[bold red]Backup integrity check failed.")
        return [], None

    try:
        data = get_fernet(passphrase, salt, use_yubi).decrypt(encrypted)
        return json.loads(data), salt
    except InvalidToken:
        console.print("[bold red]Access denied.")
        return [], None

def show_scroll(data):
    table = Table(title="Secret Scroll", show_lines=True)
    table.add_column("ID", style="cyan")
    table.add_column("Title", style="magenta")
    table.add_column("Tags", style="green")
    for idx, entry in enumerate(data):
        table.add_row(str(idx), entry["title"], ", ".join(entry.get("tags", [])))
    console.print(table)

def copy_to_clipboard(text: str):
    if not Confirm.ask("Copy secret to clipboard?", default=False):
        return
    try:
        system = platform.system()
        if system == "Linux":
            subprocess.run(['xclip', '-selection', 'clipboard'], input=text.encode(), check=True)
        elif system == "Darwin":
            subprocess.run(['pbcopy'], input=text.encode(), check=True)
        else:
            subprocess.run(['clip'], input=text.encode(), shell=True, check=True)
        console.print("[dim]Secret copied to clipboard.")
        auto_clear_clipboard()
    except Exception as e:
        console.print(f"[red]Clipboard error: {e}")

def auto_clear_clipboard():
    def clear():
        time.sleep(CLIPBOARD_TIMEOUT)
        try:
            system = platform.system()
            if system == "Linux":
                subprocess.run(['xclip', '-selection', 'clipboard'], input=b"", check=True)
            elif system == "Darwin":
                subprocess.run(['pbcopy'], input=b"", check=True)
            else:
                subprocess.run(['clip'], input=b"", shell=True, check=True)
            console.print("[dim]Clipboard cleared.")
        except:
            pass
    Thread(target=clear, daemon=True).start()


def lock_screen(use_yubi: bool):
    attempts = 0
    max_attempts = 5
    delay = 2

    with open(DATA_FILE, 'rb') as f:
        raw = f.read()
    if len(raw) < 16 + 32:
        console.print("[bold red]Corrupt data file.")
        exit(1)

    stored_salt = raw[:16]
    encrypted   = raw[16:-32]
    mac         = raw[-32:]

    yubi_required = bool(stored_salt[0] & 0x80)
    true_salt     = bytes([stored_salt[0] & 0x7F]) + stored_salt[1:]

    if yubi_required:
        use_yubi = True

    while True:
        if attempts >= max_attempts:
            console.print("[bold red]Too many failed attempts. Lockout.")
            time.sleep(delay * 2)
            attempts = 0

        entered = getpass.getpass("\n[locked] Enter passphrase: ")
        try:
            mac_key = derive_key(entered, true_salt, use_yubi)
            expected_mac = generate_hmac(base64.urlsafe_b64decode(mac_key), encrypted)
            if not hmac.compare_digest(mac, expected_mac):
                raise ValueError("Invalid HMAC")

            fernet = get_fernet(entered, true_salt, use_yubi)
            fernet.decrypt(encrypted)  # final check

            console.print("[green]Unlocked.")
            return entered, fernet
        except Exception:
            attempts += 1
            console.print(f"[red]Incorrect passphrase. ({attempts}/{max_attempts})")
            time.sleep(delay)


def main():
    console.print("[bold green]📜 Welcome to Secret Scroll!")

    if os.path.exists(DATA_FILE):
        header = open(DATA_FILE, 'rb').read(1)
        yubi_required = bool(header[0] & 0x80)
    else:
        yubi_required = False

    first_time_yubi = False
    if yubi_required:
        use_yubi = True
        console.print("[dim]YubiKey authentication is REQUIRED by your data file.")
    else:
        use_yubi = Confirm.ask("Configure YubiKey for authentication?", default=False)
        if use_yubi:
            first_time_yubi = True

    passphrase = getpass.getpass("Enter your master passphrase: ")

    if first_time_yubi:
        old_data, old_salt = load_data_with_salt(passphrase, use_yubi=False)
        new_salt = generate_salt()
        new_fernet = get_fernet(passphrase, new_salt, use_yubi=True)
        save_data(old_data, new_fernet, new_salt, passphrase, use_yubi=True)
        backup_data(old_data, new_fernet, new_salt, passphrase, use_yubi=True)
        data = old_data
        salt = new_salt
        fernet = new_fernet
    else:
        data, salt = load_data_with_salt(passphrase, use_yubi)
        fernet = get_fernet(passphrase, salt, use_yubi)

    last_active = time.time()
    locked = False

    def help_menu():
        tbl = Table(show_header=True, header_style="bold cyan")
        tbl.add_column("Command", style="magenta", no_wrap=True)
        tbl.add_column("Args", style="green")
        tbl.add_column("Description")
        for cmd, args, desc in [
            ("add", "-", "Add a new secret"),
            ("view", "[ID]", "View a secret"),
            ("edit", "[ID]", "Edit a secret"),
            ("delete", "[ID]", "Delete a secret"),
            ("search", "[title|tags] [query]", "Search secrets"),
            ("backup", "-", "Create encrypted backup"),
            ("restore", "-", "Restore from backup"),
            ("clear", "-", "Clear screen"),
            ("lock", "-", "Manually lock the session"),
            ("changepw", "-", "Change the master passphrase"),
            ("help", "-", "Show commands"),
            ("quit", "-", "Exit"),
        ]:
            tbl.add_row(cmd, args, desc)
        console.print(tbl)

    help_menu()

    while True:
        if not locked and time.time() - last_active > LOCK_TIMEOUT:
            clear_screen()
            console.print("[yellow]Session locked due to inactivity.")
            locked = True

        if locked:
            passphrase, fernet = lock_screen(use_yubi)
            locked = False
            last_active = time.time()
            continue

        cmd = Prompt.ask("\nAction (type 'help')").strip().split(maxsplit=1)
        if not cmd:
            continue

        action = cmd[0].lower()
        arg = cmd[1] if len(cmd) > 1 else None
        last_active = time.time()

        if action == "help":
            help_menu()

        elif action == "add":
            title = Prompt.ask("Title")
            secret = Prompt.ask("Secret")
            tags = Prompt.ask("Tags (comma-separated)", default="")
            data.append({
                "title": title,
                "body": secret,
                "tags": [t.strip() for t in tags.split(",") if t.strip()]
            })
            save_data(data, fernet, salt, passphrase, use_yubi)
            backup_data(data, fernet, salt, passphrase, use_yubi)

        elif action == "view":
            idx = arg or Prompt.ask("ID")
            if idx.isdigit() and int(idx) < len(data):
                entry = data[int(idx)]
                console.print(f"\n[bold]{entry['title']}[/bold]\n{entry['body']}")
                copy_to_clipboard(entry['body'])
            else:
                console.print("[red]Invalid ID.")

        elif action == "edit":
            idx = arg or Prompt.ask("ID")
            if idx.isdigit() and int(idx) < len(data):
                new_secret = Prompt.ask("New Secret")
                data[int(idx)]["body"] = new_secret
                save_data(data, fernet, salt, passphrase, use_yubi)
                backup_data(data, fernet, salt, passphrase, use_yubi)
            else:
                console.print("[red]Invalid ID.")

        elif action == "delete":
            idx = arg or Prompt.ask("ID")
            if idx.isdigit() and int(idx) < len(data):
                if Confirm.ask("Are you sure?"):
                    del data[int(idx)]
                    save_data(data, fernet, salt, passphrase, use_yubi)
                    backup_data(data, fernet, salt, passphrase, use_yubi)
            else:
                console.print("[red]Invalid ID.")

        elif action == "list":
            show_scroll(data)

        elif action == "search":
            if arg and ' ' in arg:
                field, query = arg.split(' ', 1)
            else:
                field = Prompt.ask("Search by", choices=["title", "tags"])
                query = Prompt.ask(f"Enter search term for {field}")
            query = query.lower()
            results = []
            for idx, entry in enumerate(data):
                if field == "title" and query in entry["title"].lower():
                    results.append((idx, entry))
                elif field == "tags" and any(query in tag.lower() for tag in entry.get("tags", [])):
                    results.append((idx, entry))
            if results:
                tbl = Table(title="Search Results")
                tbl.add_column("ID", style="cyan")
                tbl.add_column("Title", style="magenta")
                tbl.add_column("Tags", style="green")
                for idx, entry in results:
                    tbl.add_row(str(idx), entry["title"], ", ".join(entry.get("tags", [])))
                console.print(tbl)
            else:
                console.print("[yellow]No results found.")

        elif action == "backup":
            backup_data(data, fernet, salt, passphrase, use_yubi)
            console.print("[blue]Backup saved.")

        elif action == "restore":
            if Confirm.ask("Overwrite current data with backup?"):
                restored, new_salt = restore_backup(passphrase, use_yubi)
                if restored:
                    data = restored
                    salt = new_salt
                    fernet = get_fernet(passphrase, salt, use_yubi)
                    save_data(data, fernet, salt, passphrase, use_yubi)
                    console.print("[green]Restored from backup.")

        elif action == "clear":
            clear_screen()

        elif action == "lock":
            clear_screen()
            console.print("[yellow]Session manually locked.")
            locked = True

        elif action == "changepw":
            console.print("[bold cyan]Change Passphrase[/bold cyan]")
            current_pw = getpass.getpass("Re-enter current passphrase: ")
            try:
                test_fernet = get_fernet(current_pw, salt, use_yubi)
                test_fernet.decrypt(fernet.encrypt(json.dumps(data).encode()))
            except Exception:
                console.print("[red]Authentication failed. Passphrase not changed.")
                continue

            new_pw = getpass.getpass("New passphrase: ")
            confirm_pw = getpass.getpass("Confirm new passphrase: ")
            if new_pw != confirm_pw:
                console.print("[red]Passphrases do not match.")
                continue

            new_salt = generate_salt()
            new_fernet = get_fernet(new_pw, new_salt, use_yubi)
            save_data(data, new_fernet, new_salt, new_pw, use_yubi)
            backup_data(data, new_fernet, new_salt, new_pw, use_yubi)
            passphrase = new_pw
            salt = new_salt
            fernet = new_fernet
            console.print("[green]Passphrase updated successfully.")

        elif action == "quit":
            console.print("[bold blue]Goodbye.")
            break

        else:
            console.print(f"[red]Unknown command: {action}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted. Secrets remain safe.")
