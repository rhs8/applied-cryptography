from pathlib import Path

ctext0 = Path("ctext0").read_bytes()
ctext1 = Path("ctext1").read_bytes()

#displaying lengths
#print("Ciphertext 0 length:", len(ctext0))
#print("Ciphertext 1 length:", len(ctext1))

def xor_bytes(bytes1, bytes2):
    #XORing the cyphertexts together 
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))


def recover_text(combined, guess, position):
    guess_bytes = guess.encode("ascii")

    segment = combined[position:position + len(guess_bytes)]

    result = xor_bytes(segment, guess_bytes)

    return result

def allowed_ptxt(byte):
    return (
        32 <= byte <= 41
        or 44 <= byte <= 59
        or byte in (63, 91, 93)
        or 65 <= byte <= 90
        or 97 <= byte <= 122
    )


import re

def english_score(text):
    common_words = {
        "the", "and", "for", "are", "but",
        "not", "you", "all", "can", "had",
        "her", "was", "one", "our", "out",
        "day", "get", "has", "him", "his",
        "how", "man", "new", "now", "old",
        "see", "two", "way", "who", "its",
        "may", "use", "from", "that", "with",
        "this", "have", "been", "were", "other"
    }

    words = re.findall(r"[a-z]+", text.lower())

    return sum(word in common_words for word in words)

def validate_crib(combined, guess, position):
    guess_bytes = guess.encode("ascii")

    segment = combined[position:position + len(guess_bytes)]

    if len(segment) != len(guess_bytes):
        return False

    recovered = xor_bytes(segment, guess_bytes)

    return (
        all(allowed_ptxt(byte) for byte in guess_bytes)
        and all(allowed_ptxt(byte) for byte in recovered)
    )


def crib_drag(combined, guess):
    guess_bytes = guess.encode("ascii")
    candidates = []

    for position in range(len(combined) - len(guess_bytes) + 1):

        if validate_crib(combined, guess, position):
            segment = combined[position:position + len(guess_bytes)]
            result = xor_bytes(segment, guess_bytes)

            recovered = result.decode("ascii")
            score = english_score(recovered)

            candidates.append((score, position, recovered))

    candidates.sort(reverse=True)

    for score, position, recovered in candidates[:20]:
        print(f"Score: {score:2} | Position: {position:3} | {recovered!r}")

def scan_common_cribs(combined):
    cribs = [
        " the ", " and ", " of ", " to ",
        " in ", " is ", " that ", " for ",
        " with ", " from ", " on ",
        " by ", " was ", " are ",
        " as ", " an ", " which ",
        " their ", " it is ", " the first ",
        " one of ", " part of "
    ]

    candidates = []

    for crib in cribs:
        for position in range(len(combined) - len(crib) + 1):

            if validate_crib(combined, crib, position):
                result = recover_text(combined, crib, position)
                recovered = result.decode("ascii")
                score = english_score(recovered)

                candidates.append(
                    (score, position, crib, recovered)
                )

    candidates.sort(reverse=True)

    for score, position, crib, recovered in candidates[:30]:
        print(
            f"Score: {score:2} | Position: {position:3} | "
            f"Crib: {crib!r} | Recovered: {recovered!r}"
        )

def test_spaces(combined):
    candidates = {}

    for position, byte in enumerate(combined):
        possible_char = byte ^ 32

        if allowed_ptxt(possible_char):
            candidates[position] = chr(possible_char)

    return candidates


if __name__ == "__main__":
    combined = xor_bytes(ctext0, ctext1)
    """
    print("\nFirst 30 bytes of ctext0:", list(ctext0[:30]))
    print("First 30 bytes of ctext1:", list(ctext1[:30]))

    print("XOR of first bytes:", ctext0[0] ^ ctext1[0])
    print("First combined byte:", combined[0])

    print("Combined ciphertext length:", len(combined))
    print("First 20 XOR results:", list(combined[:20]))

    print("\nCrib-dragging results for 'and':")
    crib_drag(combined, "and")

    guess = "and".encode("ascii")
    segment = combined[321:324]
    result = xor_bytes(segment, guess)

    print(result.decode("ascii"))
    print("Combined segment:", list(combined[321:324]))
    print("Recovered bytes:", list(result))

    print("ctext0:", list(ctext0[321:324]))
    print("ctext1:", list(ctext1[321:324])) 
    
    print("\nCrib-dragging results for ' the ':")
    crib_drag(combined, " the ")

    guess = " of the "
    position = 320

    result = recover_text(combined, guess, position)

    print("Guessed text:", guess)
    print("Position:", position)
    print("Recovered bytes:", list(result))
    print("Recovered text:", result.decode("ascii"))

    candidates = test_spaces(combined)

    for position, character in candidates.items():
        print(position, character)
    """

    guess = "system, can"
    position = 357

    result = recover_text(combined, guess, position)

    print("Valid:", validate_crib(combined, guess, position))
    print("Guess:", repr(guess))
    print("Recovered:", repr(result.decode("ascii")))   
    