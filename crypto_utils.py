import secrets
import base64
import hashlib
import hmac
import subprocess
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from rich.console import Console
import config as c
import os
import json
from cryptography.fernet import InvalidToken

console = Console()                                                                                               
 
def generate_salt() -> bytes:                                                                                      
    """                                                                                                            
    Produce a 16-byte salt whose first byte's MSB is guaranteed 0,                                                 
    so we can use that bit as a flag in stored_salt.                                                               
    """                                                                                                            
    raw = secrets.token_bytes(16)                                                                                  
    first = raw[0] & 0x7F                                                                                          
    return bytes([first]) + raw[1:]


def derive_key(passphrase: str, salt: bytes, use_yubi: bool) -> bytes:                                             
    kdf = PBKDF2HMAC(                                                                                              
        algorithm=hashes.SHA256(),                                                                                 
        length=32,                                                                                                 
        salt=salt,                                                                                                 
        iterations=c.KDF_ITERATIONS,                                                                               
        backend=default_backend()                                                                                  
    )                                                                                                              
    base_key = kdf.derive(passphrase.encode())                                                                     
    if use_yubi:                                                                                                   
        yubi_resp = get_yubikey_response(passphrase)                                                               
        combined = hmac.new(yubi_resp, base_key, hashlib.sha256).digest()                                          
        return base64.urlsafe_b64encode(combined)                                                                  
    else:                                                                                                          
        return base64.urlsafe_b64encode(base_key)

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

def get_fernet(passphrase: str, salt: bytes, use_yubi: bool) -> Fernet:                                            
    return Fernet(derive_key(passphrase, salt, use_yubi))                                                          
                                                                                                                   
def generate_hmac(key: bytes, data: bytes) -> bytes:                                                               
    return hmac.new(key, data, hashlib.sha256).digest()

def load_data_with_salt(passphrase: str, use_yubi: bool):                                                          
    if not os.path.exists(c.DATA_FILE):                                                                            
        return [], generate_salt()                                                                                 
                                                                                                                   
    raw = open(c.DATA_FILE, 'rb').read()                                                                           
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
