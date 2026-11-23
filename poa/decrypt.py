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


def recover_second_last_byte(target_block, previous_block, decrypted):
    r = bytearray(os.urandom(16))

    r[15] = decrypted[15] ^ 2

    for i in range(256):
        r[14] = i

        if test_block(bytes(r), target_block):
            decrypted[14] = i
            plaintext_byte = i ^ previous_block[14]
            return plaintext_byte

    raise RuntimeError("Could not recover byte 15")


def recover_remaining_bytes(target_block, decrypted):
    for pad_len in range(2, 17): #lenght 1 already discovered
        r = bytearray(os.urandom(16))

        for j in range(16 - pad_len + 1, 16):
            desired = pad_len if j == 15 else 0
            r[j] = decrypted[j] ^ desired

        position = 16 - pad_len

        for i in range(256):
            r[position] = i

            if test_block(bytes(r), target_block):
                decrypted[position] = i
                break
        else:
            raise RuntimeError(f"Could not recover byte at position {position}")


def decrypt_block(target_block, previous_block):
    r, i = find_valid_last_byte(target_block)
    k = find_padding_length(r, target_block)

    decrypted_byte, _ = recover_last_byte(i, k, previous_block)

    decrypted = bytearray(16)
    decrypted[15] = decrypted_byte

    recover_remaining_bytes(target_block, decrypted)

    plaintext_block = bytes(
        decrypted[j] ^ previous_block[j]
        for j in range(16)
    )

    return plaintext_block

def decrypt_all_blocks(iv, blocks):
    plaintext_blocks = []

    for i in range(len(blocks)):
        if i == 0:
            previous_block = iv
        else:
            previous_block = blocks[i - 1]

        plaintext_block = decrypt_block(
            blocks[i], previous_block
        )

        plaintext_blocks.append(plaintext_block)

    return b"".join(plaintext_blocks)


def remove_padding(plaintext):
    pad_len = plaintext[-1]

    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding length")

    if plaintext[-pad_len:-1] != b'\x00' * (pad_len - 1):
        raise ValueError("Invalid padding")

    return plaintext[:-pad_len]


if __name__ == "__main__":

    iv, blocks = read_ciphertext(sys.argv[1])

    plaintext = decrypt_all_blocks(iv, blocks)
    plaintext = remove_padding(plaintext)

    Path("plaintext.txt").write_bytes(plaintext)

    """
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

    decrypted = bytearray(16)
    decrypted[15] = decrypted_byte

    recover_remaining_bytes(target_block, decrypted)

    plaintext_block = bytes(
        decrypted[j] ^ previous_block[j]
        for j in range(16)
    )

    print("Intermediate block:", list(decrypted))
    print("Recovered plaintext block:", plaintext_block)

    print("Candidate:", i)
    print("Padding length:", k)
    print("Intermediate decrypted byte:", decrypted_byte)
    print("Recovered character:", chr(plaintext_byte))
    """