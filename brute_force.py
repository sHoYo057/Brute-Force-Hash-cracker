import hashlib
import itertools
import string
import sys

def hash_password(password: str, algorithm: str) -> str:
    """
    Hash the password using the specified algorithm.
    Supported algorithms: md5, sha1, sha256
    """
    try:
        hash_func = getattr(hashlib, algorithm)
    except AttributeError:
        print(f"Error: Unsupported hash algorithm '{algorithm}'. Supported: md5, sha1, sha256")
        sys.exit(1)
    return hash_func(password.encode('utf-8')).hexdigest()

def brute_force_crack(target_hash: str, algorithm: str, max_length: int) -> str:
    """
    Attempt to brute-force crack the target hash by generating all alphanumeric
    passwords up to max_length.
    """
    chars = string.ascii_letters + string.digits
    for length in range(1, max_length + 1):
        for candidate in itertools.product(chars, repeat=length):
            candidate_password = ''.join(candidate)
            candidate_hash = hash_password(candidate_password, algorithm)
            if candidate_hash == target_hash:
                return candidate_password
    return None

def main():
    if len(sys.argv) < 4:
        print("Usage: python brute_force_password_cracker.py <hash> <algorithm> <max_length>")
        print("Example: python brute_force_password_cracker.py 5d41402abc4b2a76b9719d911017c592 md5 5")
        sys.exit(1)

    target_hash = sys.argv[1]
    algorithm = sys.argv[2].lower()
    max_length = int(sys.argv[3])

    print(f"Starting brute-force cracking for hash: {target_hash} using {algorithm} with max length {max_length}...")

    result = brute_force_crack(target_hash, algorithm, max_length)
    if result:
        print(f"Password found: {result}")
    else:
        print("Password not found within the given max length.")

if __name__ == "__main__":
    main()