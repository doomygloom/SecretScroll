# 📜 Secret Scroll

A secure, terminal-based secrets manager written in Python. It allows users to store, manage, and back up encrypted secrets locally using robust cryptographic practices. Optional two-factor authentication via YubiKey challenge-response is also supported.

## Features

* AES-256 encryption using Fernet (with HMAC-SHA256 integrity)
* Key derivation with PBKDF2-HMAC-SHA256 (600,000 iterations)
* Optional hardware-backed second factor via YubiKey
* Secure file handling with user-only read/write permissions
* Auto-lock after inactivity or via command
* Auto-clear clipboard with cross-platform support
* Search, tag, edit, and manage secrets interactively
* Encrypted local backup support
* Change master passphrase securely
* Designed for Linux, macOS, and Windows terminals

## Requirements

* Python 3.8+
* Install dependencies:

```bash
pip install -r requirements.txt
```

### Optional YubiKey Support

To enable YubiKey-based challenge-response authentication:

```bash
pip install yubikey-manager
```

Ensure `ykman` CLI is installed and in your `PATH`.

Configure your YubiKey to use HMAC-SHA1 in Slot 2:

```bash
ykman otp chalresp --set-chalresp 2 hmac-sha1
```


## Usage

Run the app:

```bash
python SecretScroll.py
```

You’ll be prompted for your master passphrase and whether to use a YubiKey. This decision affects how your encryption key is derived and must remain consistent when decrypting data.

---

## Commands

![image](https://github.com/user-attachments/assets/93bc16e8-cbd5-4fd0-8568-dc770653f4f4)

## Security Notes

* Secrets are encrypted locally using a Fernet key derived from:

  * Your passphrase (via PBKDF2)
  * Optionally, a challenge-response hash from your YubiKey (Slot 2)
* All secrets and backups are stored in files with strict file permissions (`0600`)
* Clipboard contents are auto-cleared after 30 seconds
* Auto-lock triggers after 5 minutes of inactivity or immediately via `lock`
* Changing the passphrase regenerates the salt and re-encrypts all stored secrets

---

## File Structure

| File                      | Purpose                     |
| ------------------------- | --------------------------- |
| `~/.secret_scroll`        | Main encrypted data file    |
| `~/.secret_scroll_backup` | Encrypted backup of secrets |

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
