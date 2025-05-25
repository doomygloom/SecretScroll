import os

DATA_FILE = os.path.expanduser("~/.secret_scroll")                                                                 
BACKUP_FILE = os.path.expanduser("~/.secret_scroll_backup")                                                        
LOCK_TIMEOUT = 300 # 5 min                                                                                         
CLIPBOARD_TIMEOUT = 30                                                                                             
KDF_ITERATIONS = 600_000
ENABLE_CLIPBOARD = False
