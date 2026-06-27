from Crypto.Cipher import AES, PKCS1_OAEP, ChaCha20
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import time
import os
import csv
import statistics


REPEATS = 5

SIZE_LIMITS = {
    "small": 6000,
    "medium": 40000,
    "large": 60000,
}


# ---------- Helpers ----------
def load_text_file(path: str) -> bytes:
    """Read text file as UTF-8 and return bytes."""
    with open(path, "r", encoding="utf-8") as f:
        text = f.read()
    return text.encode("utf-8")

# ---------- AES ----------
def aes_encrypt_decrypt(data, key, iv):
    start_enc = time.perf_counter()
    cipher_enc = AES.new(key, AES.MODE_CFB, iv=iv)
    ciphertext = cipher_enc.encrypt(data)
    end_enc = time.perf_counter()

    start_dec = time.perf_counter()
    cipher_dec = AES.new(key, AES.MODE_CFB, iv=iv)
    plaintext = cipher_dec.decrypt(ciphertext)
    end_dec = time.perf_counter()

    assert plaintext == data, "AES decryption mismatch!"
    return end_enc - start_enc, end_dec - start_dec


# ---------- ChaCha20 ----------
def chacha_encrypt_decrypt(data, key, nonce):
    start_enc = time.perf_counter()
    cipher_enc = ChaCha20.new(key=key, nonce=nonce)
    ciphertext = cipher_enc.encrypt(data)
    end_enc = time.perf_counter()

    start_dec = time.perf_counter()
    cipher_dec = ChaCha20.new(key=key, nonce=nonce)
    plaintext = cipher_dec.decrypt(ciphertext)
    end_dec = time.perf_counter()

    assert plaintext == data, "ChaCha20 decryption mismatch!"
    return end_enc - start_enc, end_dec - start_dec


# ---------- RSA ----------
def rsa_generate_keys(bits=2048):
    key = RSA.generate(bits)
    return key.publickey(), key


def rsa_get_max_block_size(public_key, hash_len=20):
    k = public_key.size_in_bytes()
    return k - 2 * hash_len - 2


def rsa_encrypt_decrypt(data, public_key, private_key):
    cipher_enc = PKCS1_OAEP.new(public_key)
    cipher_dec = PKCS1_OAEP.new(private_key)

    max_block = rsa_get_max_block_size(public_key)

    # Encrypt in chunks
    start_enc = time.perf_counter()
    chunks = []
    for i in range(0, len(data), max_block):
        block = data[i:i + max_block]
        chunks.append(cipher_enc.encrypt(block))
    end_enc = time.perf_counter()

    ciphertext = b"".join(chunks)

    # Decrypt in chunks
    block_size = public_key.size_in_bytes()
    start_dec = time.perf_counter()
    plain_chunks = []
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        plain_chunks.append(cipher_dec.decrypt(block))
    end_dec = time.perf_counter()

    plaintext = b"".join(plain_chunks)
    assert plaintext == data, "RSA decryption mismatch!"
    return end_enc - start_enc, end_dec - start_dec


# ================== Main ==================
def main():
    print("\n[NOTE] Generating keys (AES, ChaCha20, RSA)...\n")

    aes_key = get_random_bytes(32)
    aes_iv = get_random_bytes(16)

    chacha_key = get_random_bytes(32)
    chacha_nonce = get_random_bytes(12)

    rsa_pub, rsa_priv = rsa_generate_keys()


    files = [
        ("small.txt", "small"),
        ("medium.txt", "medium"),
        ("large.txt", "large"),
    ]

    results = []
    summary_global = {}

    for filename, label in files:
        if not os.path.exists(filename):
            print(f"[WARNING] '{filename}' not found, skipping.\n")
            continue

        raw = load_text_file(filename)
        limit = SIZE_LIMITS[label]
        if len(raw) > limit:
            data = raw[:limit]
            print(f"[STEP] {label.upper()} file ({filename}), "
                  f"original size = {len(raw)} bytes -> using first {limit} bytes")
        else:
            data = raw
            print(f"[STEP] {label.upper()} file ({filename}), size = {len(raw)} bytes")
        n = len(data)
        print(f"       Running {REPEATS} trials...")

        #save time for this file
        per_file_times = {
            "AES": [],
            "ChaCha20": [],
            "RSA": [],
        }

        for trial in range(REPEATS):
            # AES
            enc, dec = aes_encrypt_decrypt(data, aes_key, aes_iv)
            results.append(("AES", label, n, enc, dec, trial))
            per_file_times["AES"].append((enc, dec))
            summary_global.setdefault(("AES", label), []).append((enc, dec))

            # ChaCha20
            enc, dec = chacha_encrypt_decrypt(data, chacha_key, chacha_nonce)
            results.append(("ChaCha20", label, n, enc, dec, trial))
            per_file_times["ChaCha20"].append((enc, dec))
            summary_global.setdefault(("ChaCha20", label), []).append((enc, dec))

            # RSA
            enc, dec = rsa_encrypt_decrypt(data, rsa_pub, rsa_priv)
            results.append(("RSA", label, n, enc, dec, trial))
            per_file_times["RSA"].append((enc, dec))
            summary_global.setdefault(("RSA", label), []).append((enc, dec))

        print(f"[DONE] Completed trials for {label.upper()}")

        # Avg file
        print(f"\n>>> AVERAGE TIMES FOR {label.upper()} (ms)")
        print(f"{'Algo':<10} {'Avg Enc':>12} {'Avg Dec':>12}")
        for algo in ["AES", "ChaCha20", "RSA"]:
            enc_list = [t[0] for t in per_file_times[algo]]
            dec_list = [t[1] for t in per_file_times[algo]]
            avg_enc = statistics.mean(enc_list) * 1000
            avg_dec = statistics.mean(dec_list) * 1000
            print(f"{algo:<10} {avg_enc:12.4f} {avg_dec:12.4f}")
        print("\n" + "-" * 45 + "\n")

    #all size's
    print("\n===== GLOBAL SUMMARY (all files, ms) =====")
    print(f"{'Algo':<10} {'File':<8} {'Bytes':<8} {'Avg Enc':>12} {'Avg Dec':>12}")

    for (algo, label), times in summary_global.items():
        enc_list = [t[0] for t in times]
        dec_list = [t[1] for t in times]
        avg_enc = statistics.mean(enc_list) * 1000
        avg_dec = statistics.mean(dec_list) * 1000
        n = next(r[2] for r in results if r[0] == algo and r[1] == label)
        print(f"{algo:<10} {label:<8} {n:<8} {avg_enc:12.4f} {avg_dec:12.4f}")
    print("\n===== BEST / AVG / WORST PER ALGORITHM (ms) =====")
    print(f"{'Algo':<10} {'BestEnc':>12} {'AvgEnc':>12} {'WorstEnc':>12} "
          f"{'BestDec':>12} {'AvgDec':>12} {'WorstDec':>12}")
    #Best-Avg-Worst cases
    for algo in ["AES", "ChaCha20", "RSA"]:
        enc_all = [r[3] for r in results if r[0] == algo]
        dec_all = [r[4] for r in results if r[0] == algo]
        if not enc_all or not dec_all:
            continue
        best_enc = min(enc_all) * 1000
        worst_enc = max(enc_all) * 1000
        avg_enc = statistics.mean(enc_all) * 1000
        best_dec = min(dec_all) * 1000
        worst_dec = max(dec_all) * 1000
        avg_dec = statistics.mean(dec_all) * 1000
        print(f"{algo:<10} {best_enc:12.4f} {avg_enc:12.4f} {worst_enc:12.4f} "
              f"{best_dec:12.4f} {avg_dec:12.4f} {worst_dec:12.4f}")

    # sava data in CSV
    with open("results_crypto.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["Algorithm", "FileLabel", "n_bytes", "EncTime_sec", "DecTime_sec", "Trial"]
        )
        for row in results:
            writer.writerow(row)

    print("\n[OK] results saved to results_crypto.csv")
    print("[END] Experiment completed.\n")


if __name__ == "__main__":
    main()
