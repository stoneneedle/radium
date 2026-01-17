#!/usr/bin/env python3

import secrets
import string
import sys

def generate_password(length: int = 32) -> str:
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    numbers = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

    alphabet = lowercase + uppercase + numbers + special

    return "".join(secrets.choice(alphabet) for _ in range(length))


def main():
    try:
        length = int(sys.argv[1]) if len(sys.argv) > 1 else 32
    except ValueError:
        raise SystemExit("Length must be an integer")

    password = generate_password(length)
    print(password)


if __name__ == "__main__":
    main()
