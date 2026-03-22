#!/usr/bin/env python3
import os, struct, tarfile, time
import multiprocessing as mp
from multiprocessing.connection import Connection
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from datetime import timedelta
from pathlib import Path

try:
    from config import ENCRYPTED_FILE, RESTORE_DIR, KEY_FILE
except ImportError:
    raise RuntimeError("Missing config.py")

# ============================================================
# Key Loader
# ============================================================
def load_key(path: str) -> bytes:
    key = Path(path).read_bytes()

    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes (got {len(key)})")

    return key


# ============================================================
# Decrypt Producer
# ============================================================
class DecryptProducer:
    MAGIC = b"ENC3"

    def __init__(self, enc_file: str, key: bytes):
        self.enc_file = enc_file
        self.key = key

    def __call__(self, send_conn: Connection):
        try:
            with open(self.enc_file, "rb") as f:
                self._run(f, send_conn)
        finally:
            try: send_conn.close()
            except: pass

    def _run(self, f, send_conn):
        if f.read(4) != self.MAGIC:
            raise ValueError("Invalid file format")

        nonce_prefix = f.read(4)
        (chunk_size,) = struct.unpack(">I", f.read(4))

        aead = ChaCha20Poly1305(self.key)
        counter = 0

        while True:
            header = f.read(4)
            if not header:
                break

            (ct_len,) = struct.unpack(">I", header)
            ct = f.read(ct_len)

            nonce = nonce_prefix + counter.to_bytes(8, "big")
            pt = aead.decrypt(nonce, ct, None)

            send_conn.send_bytes(pt)
            counter += 1


# ============================================================
# Tar Consumer
# ============================================================
class ConnReader:
    def __init__(self, conn: Connection):
        self.conn = conn
        self.buffer = bytearray()
        self.eof = False

    def read(self, n=-1):
        if n == -1:
            while True:
                try:
                    self.buffer.extend(self.conn.recv_bytes())
                except EOFError:
                    break
            out = bytes(self.buffer)
            self.buffer.clear()
            return out

        while len(self.buffer) < n and not self.eof:
            try:
                self.buffer.extend(self.conn.recv_bytes())
            except EOFError:
                self.eof = True

        out = bytes(self.buffer[:n])
        del self.buffer[:n]
        return out

    def close(self):
        try: self.conn.close()
        except: pass


class UntarConsumer:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir

    def __call__(self, recv_conn: Connection):
        os.makedirs(self.output_dir, exist_ok=True)
        reader = ConnReader(recv_conn)

        try:
            with tarfile.open(fileobj=reader, mode="r|") as tf:
                tf.extractall(self.output_dir)
        finally:
            reader.close()

        print(f"[+] Extracted to {self.output_dir}")


# ============================================================
# Controller
# ============================================================
class TarDecryptor:
    def __init__(self, enc_file, out_dir, key_file):
        self.enc_file = enc_file
        self.out_dir = out_dir
        self.key_file = key_file

    def run(self):
        start = time.time()

        if not os.path.exists(self.enc_file):
            raise SystemExit("Missing encrypted file")

        key = load_key(self.key_file)

        recv_conn, send_conn = mp.Pipe(duplex=False)

        producer = mp.Process(
            target=DecryptProducer(self.enc_file, key),
            args=(send_conn,),
        )

        consumer = mp.Process(
            target=UntarConsumer(self.out_dir),
            args=(recv_conn,),
        )

        producer.start()
        consumer.start()

        send_conn.close()
        recv_conn.close()

        producer.join()
        consumer.join()

        if producer.exitcode != 0:
            raise SystemExit("Decrypt failed")
        if consumer.exitcode != 0:
            raise SystemExit("Extract failed")

        elapsed = timedelta(seconds=time.time() - start)
        print(f"[+] Done. Time: {elapsed}")


if __name__ == "__main__":
    try:
        mp.set_start_method("spawn")
    except RuntimeError:
        pass

    TarDecryptor(ENCRYPTED_FILE, RESTORE_DIR, KEY_FILE).run()
