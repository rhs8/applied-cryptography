
from pathlib import Path
from collections import Counter
import argparse
import string


# Expected English letter frequencies, A through Z.
ENGLISH_FREQUENCIES = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702,
    0.02228, 0.02015, 0.06094, 0.06966, 0.00153,
    0.00772, 0.04025, 0.02406, 0.06749, 0.07507,
    0.01929, 0.00095, 0.05987, 0.06327, 0.09056,
    0.02758, 0.00978, 0.02360, 0.00150, 0.01974,
    0.00074
]


def load_ciphertext(file_path):

    path = Path(file_path)

    return path.read_text(encoding="utf-8").upper()


def prepare_ciphertext(ciphertext):

    return ''.join(
        char for char in ciphertext
        if char in string.ascii_uppercase
    )


def calculate_ic(text):

    N = len(text)

    if N < 2:
        return 0.0

    frequencies = Counter(text)

    numerator = sum(
        f * (f - 1)
        for f in frequencies.values()
    )

    denominator = N * (N - 1)

    return numerator / denominator


def calculate_average_ic(letters, key_length):

    groups = [
        letters[i::key_length]
        for i in range(key_length)
    ]

    group_ics = [
        calculate_ic(group)
        for group in groups
        if len(group) >= 2
    ]

    if not group_ics:
        return 0.0

    return sum(group_ics) / len(group_ics)


def estimate_key_length(letters, min_length=5, max_length=20):

    scores = {}

    print("\nKey Length Analysis")
    print("-------------------")

    for key_length in range(min_length, max_length + 1):

        score = calculate_average_ic(letters, key_length)

        scores[key_length] = score

        print(
            f"Key length: {key_length:2d} | "
            f"Average IC: {score:.5f}"
        )

    best_score = max(scores.values())

    tolerance = 0.002

    candidates = [
        length
        for length, score in scores.items()
        if score >= best_score - tolerance
    ]

    best_length = min(candidates)

    print("\nEstimated key length:", best_length)

    return best_length


def calculate_chi_squared(text):

    N = len(text)

    if N == 0:
        return float('inf')

    frequencies = Counter(text)

    chi_squared = 0.0

    for i, letter in enumerate(string.ascii_uppercase):

        observed = frequencies[letter]

        expected = ENGLISH_FREQUENCIES[i] * N

        chi_squared += (
            (observed - expected) ** 2
        ) / expected

    return chi_squared


def find_best_shift(group):

    best_shift = 0
    lowest_score = float('inf')

    for shift in range(26):

        decrypted = ''.join(
            chr(
                (ord(char) - ord('A') - shift) % 26
                + ord('A')
            )
            for char in group
        )

        score = calculate_chi_squared(decrypted)

        if score < lowest_score:
            lowest_score = score
            best_shift = shift

    return best_shift, lowest_score


def recover_key(letters, key_length):

    key = ""

    print("\nKey Recovery")
    print("------------")

    for i in range(key_length):

        group = letters[i::key_length]

        shift, score = find_best_shift(group)

        key_letter = chr(shift + ord('A'))

        key += key_letter

        print(
            f"Group {i + 1}: "
            f"Shift = {shift:2d}, "
            f"Key letter = {key_letter}, "
            f"Chi-Squared = {score:.2f}"
        )

    print("\nCandidate key:", key)

    return key


def decrypt_vigenere(ciphertext, key):

    plaintext = ""
    key_index = 0

    for char in ciphertext:

        if char in string.ascii_uppercase:

            cipher_value = ord(char) - ord('A')

            key_value = ord(
                key[key_index % len(key)]
            ) - ord('A')

            plain_value = (
                cipher_value - key_value
            ) % 26

            plaintext += chr(plain_value + ord('A'))

            key_index += 1

        else:
            plaintext += char

    return plaintext


def encrypt_vigenere(plaintext, key):

    ciphertext = ""
    key_index = 0

    for char in plaintext:

        if char in string.ascii_uppercase:

            plain_value = ord(char) - ord('A')

            key_value = ord(
                key[key_index % len(key)]
            ) - ord('A')

            cipher_value = (
                plain_value + key_value
            ) % 26

            ciphertext += chr(cipher_value + ord('A'))

            key_index += 1

        else:
            ciphertext += char

    return ciphertext


def main():
    parser = argparse.ArgumentParser(
        description="Vigenere Cipher Cryptanalysis Tool"
    )

    parser.add_argument(
        "input",
        help="Path to the ciphertext text file"
    )

    parser.add_argument(
        "--min-key-length",
        type=int,
        default=5,
        help="Minimum key length to test (default: 5)"
    )

    parser.add_argument(
        "--max-key-length",
        type=int,
        default=20,
        help="Maximum key length to test (default: 20)"
    )

    parser.add_argument(
        "--key-length",
        type=int,
        help="Specify a key length instead of estimating it"
    )

    parser.add_argument(
        "--output",
        help="Path for the decrypted output file"
    )

    args = parser.parse_args()

    if args.min_key_length < 1:
        parser.error("Minimum key length must be positive.")

    if args.max_key_length < args.min_key_length:
        parser.error("Maximum key length must be at least the minimum.")

    if args.key_length is not None and args.key_length < 1:
        parser.error("Specified key length must be positive.")


    ciphertext = load_ciphertext(args.input)

    letters = prepare_ciphertext(ciphertext)

    if len(letters) < 2:
        parser.error("Ciphertext must contain at least two letters.")

    print("Ciphertext Analysis")
    print("-------------------")
    print("Total characters:", len(ciphertext))
    print("Total letters:", len(letters))

    if args.key_length is not None:
        key_length = args.key_length
        print("\nUsing specified key length:", key_length)

    else:
        key_length = estimate_key_length(
            letters,
            args.min_key_length,
            args.max_key_length
        )

    if key_length > len(letters):
        parser.error("Key length cannot exceed the number of letters.")

    key = recover_key(letters, key_length)

    plaintext = decrypt_vigenere(ciphertext, key)

    print("\nDecrypted Plaintext Preview")
    print("---------------------------")
    print(plaintext[:300])

    if args.output:
        output_path = Path(args.output)
    else:
        input_path = Path(args.input)
        output_path = input_path.with_name(
            input_path.stem + "_plaintext.txt"
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)

    output_path.write_text(plaintext, encoding="utf-8")

    print("\nPlaintext saved to:", output_path)

    re_encrypted = encrypt_vigenere(plaintext, key)

    print("\nRound-trip Verification")
    print("-----------------------")
    print("Matches original:", re_encrypted == ciphertext)


if __name__ == "__main__":
    main()
