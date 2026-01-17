# ---------- Configurable variables ----------
from argon2 import Type

# The password used for encryption/decryption
PASSWORD = "generatedkeygenkeyhere"


# Up (tarring/encryption)
SOURCE_DIR = r"C:\Users\username\Downloads\directory_to_upload"
OUT_DIR = r"C:\Users\username\OneDrive\output_directory"


# Down (decryption/untarring)
ENCRYPTED_FILE = r"C:\Users\username\Downloads\0ce01b5e-44f8-4c23-92bd-3fc6b333aefd.tar.enc"
RESTORE_DIR = r"C:\Users\username\Downloads\restored"
MAGIC = b"ENC2" # Magic bytes to identify the file format


# Argon2 parameters
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_TYPE = Type.ID