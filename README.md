# Radium Cryptarchiver

This repo contains 3 scripts:

**up.py**: Takes a directory tree and tars it, encrypting the tar file using chacha20 and argon2 for key stretching.  
**down.py**: Decrypts the encrypted file and untars it, restoring a directory tree for use.  
**keygen.py**: Generates a secure key for symmetric encryption/decryption.

# Configuration

In config.py, the main lines to change are as follows:

```py
# The password used for encryption/decryption
PASSWORD = "generatedkeygenkeyhere"

# Up (tarring/encryption)
SOURCE_DIR = r"C:\Users\username\Downloads\directory_to_upload"
OUT_DIR = r"C:\Users\username\OneDrive\output_directory"

# Down (decryption/untarring)
ENCRYPTED_FILE = r"C:\Users\username\Downloads\0ce01b5e-44f8-4c23-92bd-3fc6b333aefd.tar.enc"
RESTORE_DIR = r"C:\Users\username\Downloads\restored"
```

Change the password to a key generated using the keygen.py script.

Change username to your username as needed (Windows-style paths are used with Python raw strings in the example), or use forward-slashes for POSIX-compatible systems (MacOS, Linux, etc.). Change directory paths as desired.

The variables represent the following:  

**PASSWORD**: The symmetric key used to encrypt the archive.  
**SOURCE_DIR**: The source directory that is tarred and encrypted. Used in up.py.  
**OUT_DIR**: Where the encrypted output file is placed after it is tarred and encrypted. Used by up.py.  
**ENCRYPTED_FILE**: The encrypted file to be decrypted and untarred. Used by down.py.  
**RESTORE_DIR:** Where to place the restored (decrypted/untarred) directory tree. Used by down.py.  

# Logging Added

Logging has been added to upload, so that an archive contains a guide to the directory name and desired data can be restored as needed.