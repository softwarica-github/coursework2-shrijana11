import hashlib

def generate_sha1_hash(input_string):
    sha1_hash = hashlib.sha1(input_string.encode()).hexdigest()
    return sha1_hash

# Example usage
input_string = "asdfnmko9"
sha1_hash = generate_sha1_hash(input_string)
print(f"Input String: {input_string}")
print(f"SHA-1 Hash: {sha1_hash}")
