from pathlib import Path
import secrets

KEY_SIZE = 32  # 256 bits

def generate_key_file(path: str | Path) -> None:
    key_path = Path(path)

    if key_path.exists():
        raise FileExistsError(f"Refusing to overwrite existing key: {key_path}")

    key = secrets.token_bytes(KEY_SIZE)  # cryptographically secure

    with key_path.open("xb") as f:  # 'x' = fail if exists (atomic safety)
        f.write(key)

    # Restrict permissions (Unix/macOS)
    try:
        key_path.chmod(0o600)
    except PermissionError:
        pass


if __name__ == "__main__":
    generate_key_file("james_cc20_p1305_03222026.key")