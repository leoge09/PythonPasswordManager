import hashlib

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

if __name__ == "__main__":
    print(hash_password("example_password"))