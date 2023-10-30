from hmac import digest
import random, sys
from cryptography.hazmat.primitives import hashes

HASH_TO_USE = "384"
HASHES = {
    "MD5": hashes.MD5,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512
    }

def count_diff_bits(original, new):
    result = 0
    for i in range(len(original)):
        result += (original[i] ^ new[i]).bit_count()

    return result

def digest(message):
    digest = hashes.Hash(HASHES[HASH_TO_USE]())
    digest.update(message)
    return digest.finalize()

def main(size, num_messages):
    initial_message = random.randbytes(size)
    initial_message_dig = digest(initial_message)

    track_mods = [0] * size
    histogram = [0] * (HASHES[HASH_TO_USE].digest_size * 8 + 1)
    for i in range(num_messages):
        while True:
            byte_change = random.randrange(0, size)
            bit_change = random.randrange(0, 8)
            bit_mask = 1 << bit_change
            if not track_mods[byte_change] & bit_mask:
                break
        
        track_mods[byte_change] |= bit_mask

        new_message = initial_message[:byte_change] + (initial_message[byte_change] ^ bit_mask).to_bytes + initial_message[byte_change + 1:]

        histogram[count_diff_bits(original=initial_message_dig, new=digest(new_message))] += 1
    
    for i in range(len(histogram)):
        print(f"{i}\t{'+' * histogram[i]}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage:\n\tpythonc{sys.argv[0]}  M   N\n\n"
              "\tM: the size in bytes of the initial source message\n"
              "\tN: the number of on-bit altered messages\n"
              "\n")
        exit(-2)
    main(size=int(sys.argv[1]), num_messages=int(sys.argv[2]))
