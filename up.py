#!/usr/bin/env python3
import os, struct, time, tarfile, uuid, logging
import multiprocessing as mp
from multiprocessing.connection import Connection
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import timedelta

try:
    from config import SOURCE_DIR, OUT_DIR, PASSWORD
except ImportError:
    raise RuntimeError(
        "Missing config.py. Copy config.example.py to config.py and edit it."
    )

# -------------------- Logging --------------------
# App Logger
app_formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
app_logger = logging.getLogger("app_logger")
app_logger.setLevel(logging.DEBUG)
app_handler = logging.FileHandler("logs/app.log")
app_handler.setFormatter(app_formatter)
app_logger.addHandler(app_handler)

# File Logger
file_formatter = logging.Formatter("[%(asctime)s] %(message)s")
file_logger = logging.getLogger("file_logger")
file_logger.setLevel(logging.INFO)
file_handler = logging.FileHandler("logs/files.log")
file_handler.setFormatter(file_formatter)
file_logger.addHandler(file_handler)


# ============================================================
#  Key Derivation
# ============================================================
class KeyDeriver:
    def __init__(self, time_cost=3, mem_cost=64*1024, parallelism=4, hash_len=32):
        self.time_cost = time_cost
        self.mem_cost = mem_cost
        self.parallelism = parallelism
        self.hash_len = hash_len
        self.type = Type.ID

    def derive(self, password: str, salt: bytes) -> bytes:
        # Debug
        app_logger.debug(f"Deriving key for password: {password}")
        app_logger.debug(f"Salt (hex): {salt.hex()}")
        app_logger.debug(f"Parameters - time_cost: {self.time_cost}, mem_cost: {self.mem_cost}, parallelism: {self.parallelism}, hash_len: {self.hash_len}, type: {self.type}")

        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=self.time_cost,
            memory_cost=self.mem_cost,
            parallelism=self.parallelism,
            hash_len=self.hash_len,
            type=self.type,
        )


# ============================================================
#  Tar Streaming Producer (Process-target class)
# ============================================================
class TarStreamer:
    """Runs inside a subprocess. Writes tar bytes into send_conn."""

    class ConnWriter:
        def __init__(self, conn: Connection):
            self._conn = conn

        def write(self, data: bytes):
            if data:
                self._conn.send_bytes(data)

        def flush(self):
            pass

        def close(self):
            try:
                self._conn.close()
            except:
                pass

    @staticmethod
    def run(send_conn: Connection, source_dir: str):
        """Static method so it can be used as mp.Process target."""
        try:
            writer = TarStreamer.ConnWriter(send_conn)
            base = os.path.basename(os.path.normpath(source_dir))

            with tarfile.open(fileobj=writer, mode="w|") as tf:
                tf.add(source_dir, arcname=base)
                app_logger.debug(f"Tar streaming completed for directory: {source_dir}")

            writer.close()

        except Exception as e:
            app_logger.error(f"Error in TarStreamer: {e}")
            try: send_conn.close()
            except: pass
            raise


# ============================================================
#  Encryption Consumer (Process-target class)
# ============================================================
class Encryptor:
    MAGIC = b"ENC2"

    @staticmethod
    def run(recv_conn: Connection, outfile: str,
            key: bytes, salt: bytes,
            nonce_prefix: bytes, chunk_size: int):

        aead = ChaCha20Poly1305(key)

        with open(outfile, "wb") as out:
            # Write header
            out.write(Encryptor.MAGIC)
            out.write(struct.pack(">H", len(salt)))
            out.write(salt)
            out.write(nonce_prefix)
            out.write(struct.pack(">I", chunk_size))

            buffer = bytearray()
            counter = 0

            try:
                while True:
                    chunk = recv_conn.recv_bytes()  # EOFError when closed
                    #app_logger.debug(f"Encryptor received chunk of size: {len(chunk)} bytes")
                    if chunk:
                        buffer.extend(chunk)

                    while len(buffer) >= chunk_size:
                        plaintext = bytes(buffer[:chunk_size])
                        del buffer[:chunk_size]

                        nonce = nonce_prefix + counter.to_bytes(8, "big")
                        ct = aead.encrypt(nonce, plaintext, None)
                        out.write(struct.pack(">I", len(ct)))
                        out.write(ct)
                        counter += 1

            except EOFError:
                pass

            # Final partial block
            if buffer:
                nonce = nonce_prefix + counter.to_bytes(8, "big")
                ct = aead.encrypt(nonce, bytes(buffer), None)
                out.write(struct.pack(">I", len(ct)))
                out.write(ct)
                counter += 1

        try: recv_conn.close()
        except: pass

        #print(f"[+] Finished encryption -> {outfile} (chunks: {counter})")
        #file_logger.info(f"[+] {os.path.basename(SOURCE_DIR)} :: {outfile} ")


# ============================================================
#  Main Orchestrator Class
# ============================================================
class CryptoArchiver:
    def __init__(self, source_dir: str, out_dir: str, password: str,
                 chunk_size=64*1024):
        self.source_dir = source_dir
        self.out_dir = out_dir
        self.password = password
        self.chunk_size = chunk_size

        self.archive_name = str(uuid.uuid4()) + ".tar.enc"
        self.outfile = os.path.join(out_dir, self.archive_name)

        self.kdf = KeyDeriver()

    def run(self):
        start = time.time()

        if not os.path.exists(self.source_dir):
            raise SystemExit("Source directory not found: " + self.source_dir)

        salt = os.urandom(16)
        key = self.kdf.derive(self.password, salt)
        nonce_prefix = os.urandom(4)

        recv_conn, send_conn = mp.Pipe(duplex=False)

        producer = mp.Process(
            target=TarStreamer.run,
            args=(send_conn, self.source_dir),
            name="tar-producer"
        )
        consumer = mp.Process(
            target=Encryptor.run,
            args=(recv_conn, self.outfile, key, salt, nonce_prefix, self.chunk_size),
            name="encrypt-consumer"
        )

        producer.start()
        consumer.start()

        # Parent closes proxies
        send_conn.close()
        recv_conn.close()

        producer.join()
        consumer.join()

        if producer.exitcode != 0:
            raise SystemExit(f"Producer failed (exit {producer.exitcode})")
        if consumer.exitcode != 0:
            raise SystemExit(f"Consumer failed (exit {consumer.exitcode})")

        elapsed = timedelta(seconds=time.time() - start)

        file_logger.info(f"[+] {os.path.basename(SOURCE_DIR)} :: {self.archive_name} ")

        print(f"[+] All done. Time: {elapsed}")
        print(f"Output file: {self.outfile}")


# ============================================================
#  Entry Point
# ============================================================
if __name__ == "__main__":
    try:
        mp.set_start_method("spawn")
    except RuntimeError:
        pass

    app = CryptoArchiver(SOURCE_DIR, OUT_DIR, PASSWORD)
    app.run()
