from flask import Flask, render_template, request
import hashlib
import itertools
import string

app = Flask(__name__)

def hash_password(password: str, algorithm: str) -> str:
    try:
        hash_func = getattr(hashlib, algorithm)
    except AttributeError:
        return None
    return hash_func(password.encode('utf-8')).hexdigest()

def brute_force_crack(target_hash: str, algorithm: str, max_length: int = 5) -> str:
    chars = string.ascii_letters + string.digits
    for length in range(1, max_length + 1):
        for candidate in itertools.product(chars, repeat=length):
            candidate_password = ''.join(candidate)
            candidate_hash = hash_password(candidate_password, algorithm)
            if candidate_hash == target_hash:
                return candidate_password
    return None

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    if request.method == 'POST':
        target_hash = request.form.get('target_hash', '').strip()
        algorithm = request.form.get('algorithm', '').strip().lower()
        max_length_str = request.form.get('max_length', '').strip()

        if not target_hash or not algorithm:
            error = "Please provide both target hash and algorithm."
        else:
            try:
                max_length = int(max_length_str) if max_length_str else 5
                if max_length < 1:
                    error = "Max length must be a positive integer."
            except ValueError:
                error = "Max length must be an integer."
            
            if not error:
                cracked = brute_force_crack(target_hash, algorithm, max_length)
                if cracked:
                    result = f"Password found: {cracked}"
                else:
                    result = "Password not found within the given max length."

    return render_template('index.html', result=result, error=error)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)