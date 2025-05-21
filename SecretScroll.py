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
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import hmac
import hashlib

# X: @owldecoy

DATA_FILE = os.path.expanduser("~/.secret_scroll")
BACKUP_FILE = os.path.expanduser("~/.secret_scroll_backup")
LOCK_TIMEOUT = 300  # 5 minutes
CLIPBOARD_TIMEOUT = 30
KDF_ITERATIONS = 600_000

console = Console()

def clear_screen():
    os.system("cls" if platform.system() == "Windows" else "clear")

def get_yubikey_response(challenge: bytes) -> bytes:
    try:
        result = subprocess.run(
            ['ykman', 'otp', 'chalresp', '2', base64.b64encode(challenge).decode()],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True
        )
        return base64.b64decode(result.stdout.strip())
    except Exception as e:
        console.print(f"[red]YubiKey challenge failed: {e}")
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
        yubi_resp = get_yubikey_response(salt)
        combined = hmac.new(yubi_resp, base_key, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(combined)
    else:
        return base64.urlsafe_b64encode(base_key)

def get_fernet(passphrase: str, salt: bytes, use_yubi: bool) -> Fernet:
    return Fernet(derive_key(passphrase, salt, use_yubi))

def write_secure_file(path, content: bytes):
    with open(path, 'wb') as f:
        f.write(content)
    os.chmod(path, 0o600)

def load_data_with_salt(passphrase: str, use_yubi: bool):
    if not os.path.exists(DATA_FILE):
        return [], secrets.token_bytes(16)

    with open(DATA_FILE, 'rb') as f:
        raw = f.read()

    if len(raw) < 16:
        console.print("[bold red]Corrupt data file.")
        exit(1)

    salt = raw[:16]
    encrypted = raw[16:]

    try:
        data = get_fernet(passphrase, salt, use_yubi).decrypt(encrypted)
        return json.loads(data), salt
    except InvalidToken:
        console.print("[bold red]Access denied.")
        exit(1)

def save_data(data, fernet: Fernet, salt: bytes):
    encrypted = fernet.encrypt(json.dumps(data).encode())
    write_secure_file(DATA_FILE, salt + encrypted)

def backup_data(data, fernet: Fernet, salt: bytes):
    encrypted = fernet.encrypt(json.dumps(data).encode())
    write_secure_file(BACKUP_FILE, salt + encrypted)

def restore_backup(passphrase: str, use_yubi: bool):
    if not os.path.exists(BACKUP_FILE):
        return [], None

    with open(BACKUP_FILE, 'rb') as f:
        raw = f.read()

    if len(raw) < 16:
        console.print("[bold red]Corrupt backup file.")
        return [], None

    salt = raw[:16]
    encrypted = raw[16:]

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

def copy_to_clipboard(text):
    try:
        system = platform.system()
        if system == "Linux":
            subprocess.run(['xclip', '-selection', 'clipboard'], input=text.encode(), check=True)
        elif system == "Darwin":
            subprocess.run(['pbcopy'], input=text.encode(), check=True)
        elif system == "Windows":
            subprocess.run(['clip'], input=text.encode(), shell=True, check=True)
        console.print("[dim]Secret copied to clipboard.")
    except Exception as e:
        console.print(f"[red]Clipboard error: {e}")

def auto_clear_clipboard():
    def clear_clip():
        time.sleep(CLIPBOARD_TIMEOUT)
        try:
            if platform.system() == "Linux":
                subprocess.run(['xclip', '-selection', 'clipboard'], input=b"", check=True)
            elif platform.system() == "Darwin":
                subprocess.run(['pbcopy'], input=b"", check=True)
            elif platform.system() == "Windows":
                subprocess.run(['clip'], input=b"", shell=True, check=True)
            console.print("[dim]Clipboard cleared.")
        except:
            pass
    Thread(target=clear_clip, daemon=True).start()

def lock_screen(salt, use_yubi):
    while True:
        entered = getpass.getpass("\n[locked] Enter passphrase: ")
        try:
            f = get_fernet(entered, salt, use_yubi)
            f.decrypt(f.encrypt(b"test"))
            console.print("[green]Unlocked.")
            return entered, f
        except:
            console.print("[red]Incorrect passphrase.")

def main():
    console.print("[bold green]Welcome to Secret Scroll 🧙♂")

    use_yubi = Confirm.ask("Use YubiKey for authentication?", default=False)
    passphrase = getpass.getpass("Enter your master passphrase: ")

    data, salt = load_data_with_salt(passphrase, use_yubi)
    fernet = get_fernet(passphrase, salt, use_yubi)
    last_active = time.time()
    locked = False

    def help_menu():
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Command", style="magenta", no_wrap=True)
        table.add_column("Args", style="green")
        table.add_column("Description")
        table.add_row("add", "-", "Add a new secret")
        table.add_row("view", "[ID]", "View a secret")
        table.add_row("edit", "[ID]", "Edit a secret")
        table.add_row("delete", "[ID]", "Delete a secret")
        table.add_row("search", r"\[title|tags] \[query]", "Search secrets")
        table.add_row("search", "[title|tags] [query]", "Search secrets")
        table.add_row("backup", "-", "Create encrypted backup")
        table.add_row("restore", "-", "Restore from backup")
        table.add_row("clear", "-", "Clear screen")
        table.add_row("lock", "-", "Manually lock the session")
        table.add_row("changepw", "-", "Change the master passphrase")
        table.add_row("help", "-", "Show commands")
        table.add_row("quit", "-", "Exit")
        console.print(table)

    help_menu()

    while True:
        if not locked and time.time() - last_active > LOCK_TIMEOUT:
            clear_screen()
            console.print("[yellow]Session locked due to inactivity.")
            locked = True

        if locked:
            passphrase, fernet = lock_screen(salt, use_yubi)
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
            data.append({"title": title, "body": secret, "tags": [t.strip() for t in tags.split(",") if t.strip()]})
            save_data(data, fernet, salt)
            backup_data(data, fernet, salt)

        elif action == "view":
            idx = arg or Prompt.ask("ID")
            if idx.isdigit() and int(idx) < len(data):
                entry = data[int(idx)]
                console.print(f"\n[bold]{entry['title']}[/bold]\n{entry['body']}")
                copy_to_clipboard(entry['body'])
                auto_clear_clipboard()
            else:
                console.print("[red]Invalid ID.")

        elif action == "edit":
            idx = arg or Prompt.ask("ID")
            if idx.isdigit() and int(idx) < len(data):
                new_secret = Prompt.ask("New Secret")
                data[int(idx)]["body"] = new_secret
                save_data(data, fernet, salt)
                backup_data(data, fernet, salt)
            else:
                console.print("[red]Invalid ID.")

        elif action == "delete":
            idx = arg or Prompt.ask("ID")
            if idx.isdigit() and int(idx) < len(data):
                if Confirm.ask("Are you sure?"):
                    del data[int(idx)]
                    save_data(data, fernet, salt)
                    backup_data(data, fernet, salt)
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
                table = Table(title="Search Results")
                table.add_column("ID", style="cyan")
                table.add_column("Title", style="magenta")
                table.add_column("Tags", style="green")
                for idx, entry in results:
                    table.add_row(str(idx), entry["title"], ", ".join(entry.get("tags", [])))
                console.print(table)
            else:
                console.print("[yellow]No results found.")

        elif action == "backup":
            backup_data(data, fernet, salt)
            console.print("[blue]Backup saved.")

        elif action == "restore":
            if Confirm.ask("Overwrite current data with backup?"):
                restored, new_salt = restore_backup(passphrase, use_yubi)
                if restored:
                    data = restored
                    salt = new_salt
                    fernet = get_fernet(passphrase, salt, use_yubi)
                    save_data(data, fernet, salt)
                    console.print("[green]Restored from backup.")

        elif action == "clear":
            clear_screen()

        elif action == "lock":
            clear_screen()
            console.print("[yellow]Session manually locked.")
            locked = True

        elif action == "quit":
            console.print("[bold blue]Goodbye.")
            break

        elif action == "changepw":
            console.print("[bold cyan]Change Passphrase[/bold cyan]")
    
            current_pw = getpass.getpass("Re-enter current passphrase: ")
            try:
                test_fernet = get_fernet(current_pw, salt, use_yubi)
                test_fernet.decrypt(test_fernet.encrypt(b"test"))
            except:
                console.print("[red]Authentication failed. Passphrase not changed.")
                continue

            new_pw = getpass.getpass("New passphrase: ")
            confirm_pw = getpass.getpass("Confirm new passphrase: ")
    
            if new_pw != confirm_pw:
                console.print("[red]Passphrases do not match.")
                continue

            new_salt = secrets.token_bytes(16)
            new_fernet = get_fernet(new_pw, new_salt, use_yubi)

            save_data(data, new_fernet, new_salt)
            backup_data(data, new_fernet, new_salt)

            passphrase = new_pw
            salt = new_salt
            fernet = new_fernet

            console.print("[green]Passphrase updated successfully.")

        else:
            console.print(f"[red]Unknown command: {action}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Interrupted. Secrets remain safe.")
      
