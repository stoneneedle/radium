#!/usr/bin/env python3
import os, struct, time, tarfile, uuid, logging
import multiprocessing as mp
from multiprocessing.connection import Connection
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import timedelta
from pathlib import Path

try:
    from config import SOURCE_DIR, OUT_DIR, KEY_FILE
except ImportError:
    raise RuntimeError("Missing config.py")

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
# Key Loader
# ============================================================
def load_key(path: str) -> bytes:
    key = Path(path).read_bytes()

    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes (got {len(key)})")

    return key


# ============================================================
# Tar Streaming Producer
# ============================================================
class TarStreamer:
    class ConnWriter:
        def __init__(self, conn: Connection):
            self.conn = conn

        def write(self, data: bytes):
            if data:
                self.conn.send_bytes(data)

        def flush(self): pass

        def close(self):
            try: self.conn.close()
            except: pass

    @staticmethod
    def run(send_conn: Connection, source_dir: str):
        try:
            writer = TarStreamer.ConnWriter(send_conn)
            base = os.path.basename(os.path.normpath(source_dir))

            with tarfile.open(fileobj=writer, mode="w|") as tf:
                tf.add(source_dir, arcname=base)

            writer.close()

        except Exception as e:
            app_logger.error(f"TarStreamer error: {e}")
            try: send_conn.close()
            except: pass
            raise


# ============================================================
# Encryptor (Consumer)
# ============================================================
class Encryptor:
    MAGIC = b"ENC3"

    @staticmethod
    def run(recv_conn: Connection, outfile: str,
            key: bytes, nonce_prefix: bytes, chunk_size: int):

        aead = ChaCha20Poly1305(key)

        with open(outfile, "wb") as out:
            # Header
            out.write(Encryptor.MAGIC)
            out.write(nonce_prefix)
            out.write(struct.pack(">I", chunk_size))

            buffer = bytearray()
            counter = 0

            try:
                while True:
                    chunk = recv_conn.recv_bytes()
                    if chunk:
                        buffer.extend(chunk)

                    while len(buffer) >= chunk_size:
                        pt = bytes(buffer[:chunk_size])
                        del buffer[:chunk_size]

                        nonce = nonce_prefix + counter.to_bytes(8, "big")
                        ct = aead.encrypt(nonce, pt, None)

                        out.write(struct.pack(">I", len(ct)))
                        out.write(ct)

                        counter += 1

            except EOFError:
                pass

            if buffer:
                nonce = nonce_prefix + counter.to_bytes(8, "big")
                ct = aead.encrypt(nonce, bytes(buffer), None)

                out.write(struct.pack(">I", len(ct)))
                out.write(ct)

        try: recv_conn.close()
        except: pass


# ============================================================
# Main Controller
# ============================================================
class CryptoArchiver:
    def __init__(self, source_dir, out_dir, key_file, chunk_size=64*1024):
        self.source_dir = source_dir
        self.out_dir = out_dir
        self.key_file = key_file
        self.chunk_size = chunk_size

        self.archive_name = str(uuid.uuid4()) + ".tar.enc"
        self.outfile = os.path.join(out_dir, self.archive_name)

    def run(self):
        start = time.time()

        if not os.path.exists(self.source_dir):
            raise SystemExit("Missing source dir")

        key = load_key(self.key_file)
        nonce_prefix = os.urandom(4)

        recv_conn, send_conn = mp.Pipe(duplex=False)

        producer = mp.Process(
            target=TarStreamer.run,
            args=(send_conn, self.source_dir),
        )

        consumer = mp.Process(
            target=Encryptor.run,
            args=(recv_conn, self.outfile, key, nonce_prefix, self.chunk_size),
        )

        producer.start()
        consumer.start()

        send_conn.close()
        recv_conn.close()

        producer.join()
        consumer.join()

        if producer.exitcode != 0:
            raise SystemExit("Producer failed")
        if consumer.exitcode != 0:
            raise SystemExit("Encryptor failed")

        elapsed = timedelta(seconds=time.time() - start)

        file_logger.info(f"[+] {os.path.basename(SOURCE_DIR)} :: {self.archive_name} ")
        print(f"[+] Done: {self.outfile}")
        print(f"Time: {elapsed}")

# ============================================================
#  Entry Point
# ============================================================
if __name__ == "__main__":
    try:
        mp.set_start_method("spawn")
    except RuntimeError:
        pass

    CryptoArchiver(SOURCE_DIR, OUT_DIR, KEY_FILE).run()
