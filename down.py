#!/usr/bin/env python3
"""
OOP version of the multiprocess streaming decrypt → untar pipeline.

Processes:
    - DecryptProducer: Reads encrypted file, decrypts, streams plaintext tar bytes.
    - UntarConsumer: Receives plaintext bytes and extracts using tarfile "r|" mode.

File format:
    MAGIC (4 bytes)
    uint16 salt_len
    salt
    nonce_prefix (4 bytes)
    uint32 chunk_size
    repeated:
        uint32 ct_len
        ct_bytes
"""

import os, struct, tarfile, time
import multiprocessing as mp
from multiprocessing.connection import Connection
from tracemalloc import start
from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import timedelta

try:
    from config import ENCRYPTED_FILE, RESTORE_DIR, PASSWORD, MAGIC, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM, ARGON2_HASH_LEN, ARGON2_TYPE
except ImportError:
    raise RuntimeError(
        "Missing config.py. Copy config.example.py to config.py and edit it."
    )

# ============================================================
# Base Utility: Key Derivation
# ============================================================
class KeyDeriver:
    @staticmethod
    def derive(password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_COST,
            parallelism=ARGON2_PARALLELISM,
            hash_len=ARGON2_HASH_LEN,
            type=ARGON2_TYPE,
        )


# ============================================================
# Producer: Decrypt encrypted chunks and stream plaintext tar
# ============================================================
class DecryptProducer:
    def __init__(self, enc_file: str, password: str):
        self.enc_file = enc_file
        self.password = password

    def __call__(self, send_conn: Connection):
        """Process entry point: read encrypted file, decrypt chunks, stream plaintext."""
        try:
            with open(self.enc_file, "rb") as f:
                self._process_stream(f, send_conn)
        except Exception:
            try:
                send_conn.close()
            except:
                pass
            raise

    def _process_stream(self, f, send_conn: Connection):
        # ---- Header ----
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Invalid MAGIC header")

        (salt_len,) = struct.unpack(">H", f.read(2))
        salt = f.read(salt_len)
        nonce_prefix = f.read(4)
        (chunk_size,) = struct.unpack(">I", f.read(4))

        # ---- Derive key ----
        key = KeyDeriver.derive(self.password, salt)
        aead = ChaCha20Poly1305(key)

        counter = 0

        # ---- Read encrypted chunks ----
        while True:
            header = f.read(4)
            if not header:
                break  # EOF

            (ct_len,) = struct.unpack(">I", header)
            ct = f.read(ct_len)

            if len(ct) != ct_len:
                raise ValueError("Ciphertext truncated")

            # Decrypt
            nonce = nonce_prefix + counter.to_bytes(8, "big")
            pt = aead.decrypt(nonce, ct, associated_data=None)

            # Stream plaintext tar bytes
            send_conn.send_bytes(pt)
            counter += 1

        send_conn.close()


# ============================================================
# Consumer: Receive plaintext tar bytes and extract using tarfile
# ============================================================
class ConnReader:
    """
    A file-like object used by tarfile for streaming extraction.
    """

    def __init__(self, conn: Connection):
        self.conn = conn
        self.buffer = bytearray()
        self.eof = False

    def read(self, n=-1):
        # Unbounded read (rare in tarfile but supported)
        if n == -1:
            while True:
                try:
                    chunk = self.conn.recv_bytes()
                    self.buffer.extend(chunk)
                except EOFError:
                    break
            out = bytes(self.buffer)
            self.buffer.clear()
            return out

        # Fill buffer until n bytes or EOF
        while len(self.buffer) < n and not self.eof:
            try:
                chunk = self.conn.recv_bytes()
                self.buffer.extend(chunk)
            except EOFError:
                self.eof = True
                break

        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out

    def close(self):
        try:
            self.conn.close()
        except:
            pass


class UntarConsumer:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def __call__(self, recv_conn: Connection):
        os.makedirs(self.output_dir, exist_ok=True)
        reader = ConnReader(recv_conn)

        try:
            with tarfile.open(fileobj=reader, mode="r|") as tf:
                tf.extractall(path=self.output_dir)
        finally:
            reader.close()

        print(f"[+] Extraction complete into: {self.output_dir}")


# ============================================================
# Controller / Orchestrator
# ============================================================
class TarDecryptor:
    def __init__(self, encrypted_file: str, output_dir: str, password: str):
        self.encrypted_file = encrypted_file
        self.output_dir = output_dir
        self.password = password

    def run(self):
        start = time.time()

        if not os.path.exists(self.encrypted_file):
            raise SystemExit(f"Encrypted file not found: {self.encrypted_file}")

        recv_conn, send_conn = mp.Pipe(duplex=False)

        producer = mp.Process(
            target=DecryptProducer(self.encrypted_file, self.password),
            args=(send_conn,),
            name="decrypt-producer",
        )

        consumer = mp.Process(
            target=UntarConsumer(self.output_dir),
            args=(recv_conn,),
            name="untar-consumer",
        )

        # Start processes
        producer.start()
        consumer.start()

        # Parent closes unused pipe ends
        send_conn.close()
        recv_conn.close()

        producer.join()
        consumer.join()

        if producer.exitcode != 0:
            raise SystemExit(f"Decrypt producer failed ({producer.exitcode})")
        if consumer.exitcode != 0:
            raise SystemExit(f"Untar consumer failed ({consumer.exitcode})")

        
        elapsed = timedelta(seconds=time.time() - start)
        
        print(f"[+] All done. Time: {elapsed}")


# ============================================================
# Main Entrypoint
# ============================================================
if __name__ == "__main__":
    try:
        mp.set_start_method("spawn")
    except RuntimeError:
        pass

    TarDecryptor(
        encrypted_file=ENCRYPTED_FILE,
        output_dir=RESTORE_DIR,
        password=PASSWORD
    ).run()
