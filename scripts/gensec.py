import secrets
import base64
import struct

def generate_jti():
    # Generate a 128-bit (16-byte) random number
    jti_secret = secrets.randbits(128)

    # Convert the number to big-endian bytes
    jti_bytes = struct.pack('>QQ', jti_secret >> 64, jti_secret & ((1 << 64) - 1))

    # Base64 encode the bytes
    jti_base64 = base64.urlsafe_b64encode(jti_bytes).decode('utf-8').rstrip('=')

    return jti_secret, jti_base64

# Generate and print the JTI
jti_secret, jti_base64 = generate_jti()

print(f"Secret (128-bit decimal): {jti_secret}")
print(f"Encoded (Base64 encoded): {jti_base64}")
