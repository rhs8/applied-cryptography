import subprocess
import tempfile
from pathlib import Path
import sys
import os


def oracle(ciphertext):
    with tempfile.NamedTemporaryFile(
        dir=Path(__file__).parent, delete=False
    ) as f:
        f.write(ciphertext)
        filename = f.name

    try:
        result = subprocess.check_output(
            ["python3", str(Path(__file__).with_name("oracle.py")), filename],
            text=True
        ).strip()
    finally:
        Path(filename).unlink()

    return result == "1"

def read_ciphertext(filename):
    data = Path(filename).read_bytes()

    if len(data) < 32 or len(data) % 16 != 0:
        raise ValueError("Invalid ciphertext length")

    iv = data[:16]

    blocks = [
        data[i:i+16]
        for i in range(16, len(data), 16)
    ]

    return iv, blocks


def test_block(previous_block, target_block):
    modified_ciphertext = previous_block + target_block
    return oracle(modified_ciphertext)


def find_valid_last_byte(target_block):
    r = bytearray(os.urandom(16))

    for i in range(256):
        r[15] = i

        if test_block(bytes(r), target_block):
            return bytes(r), i

    raise RuntimeError("No valid padding candidate found")


def find_padding_length(r, target_block):
    count = 0

    for j in range(15):
        modified = bytearray(r)
        modified[j] ^= 1

        if not test_block(bytes(modified), target_block):
            count += 1

    return count + 1


def recover_last_byte(i, k, previous_block):
    if k == 1:
        decrypted_byte = i ^ 1
    else:
        decrypted_byte = i ^ (17 - k)

    plaintext_byte = decrypted_byte ^ previous_block[15]

    return decrypted_byte, plaintext_byte


if __name__ == "__main__":

    ##ciphertext = Path("ciphertext").read_bytes()
    ##print(oracle(ciphertext))

    ##iv, blocks = read_ciphertext(sys.argv[1])

    ##print("IV length:", len(iv))
    ##print("Number of ciphertext blocks:", len(blocks))
    ##print("Block lengths:", [len(block) for block in blocks])

    iv, blocks = read_ciphertext(sys.argv[1])

    ##print(test_block(blocks[-2], blocks[-1]))

    target_block = blocks[-1]
    previous_block = blocks[-2]

    r, i = find_valid_last_byte(target_block)
    k = find_padding_length(r, target_block)

    decrypted_byte, plaintext_byte = recover_last_byte(i, k, previous_block)

    print("Candidate:", i)
    print("Padding length:", k)
    print("Intermediate decrypted byte:", decrypted_byte)
    print("Recovered byte:", plaintext_byte)
    print("Recovered character:", chr(plaintext_byte))