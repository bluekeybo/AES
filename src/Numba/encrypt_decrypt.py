from aes import AES
from ctr import CTR
import getpass
import secrets
import argparse
import concurrent.futures
import hmac
import hashlib


def encrypt_decrypt(func, in_stream, block_size):
    return b"".join(
        [
            func(in_stream[i : i + block_size], i)
            for i in range(0, len(in_stream), block_size)
        ]
    )


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", action="store_true")
    group.add_argument("-d", "--decrypt", action="store_true")
    parser.add_argument("input_file")
    parser.add_argument("output_file")
    args = parser.parse_args()

    passwd = getpass.getpass(
        "Enter {} password: ".format("encryption" if args.encrypt else "decryption")
    )

    # AES block size is 128 bits (16 bytes)
    block_size = 16

    # Read input file into memory
    with open(args.input_file, "rb") as f_in:
        file_in = f_in.read()

    # Encryption
    if args.encrypt:
        # Create a random 128 bit salt (16 bytes) used in the key derivation function
        # The salt will be stored as the first block of the ciphertext
        salt = secrets.token_bytes(block_size)

        # Create a random 10-byte nonce
        nonce = secrets.token_bytes(10)

        # Create the IV from the nonce and the initial 6-byte counter value of 0
        # The IV will be stored as the second block of the ciphertext
        IV = nonce + b"\x00" * 6

        # Start AES cipher
        cipher = AES(password_str=passwd, salt=salt, key_len=256)

        # Start CTR mode
        mode = CTR(cipher, nonce)

        file_out = salt + IV + encrypt_decrypt(mode.encrypt, file_in, block_size)

        # Create authentication HMAC and store it as the last two blocks of the file
        hmac_val = hmac.digest(key=cipher.hmac_key, msg=file_out, digest=hashlib.sha256)

        # Append HMAC to the ciphertext
        file_out += hmac_val

    # Decryption
    else:
        # Extract the salt from the first 128 bits (16 bytes) of the ciphertext
        salt = file_in[0:block_size]

        # Extract nonce from the first 10 bytes of the second block of the ciphertext
        nonce = file_in[block_size : block_size + 10]

        # Extract the HMAC value from the last 2 blocks of the ciphertext
        hmac_val = file_in[-2 * block_size :]

        # Start AES cipher
        cipher = AES(password_str=passwd, salt=salt, key_len=256)

        # Compare HMAC values (remove the HMAC value from the ciphertext before comparing)
        assert hmac.compare_digest(
            hmac_val,
            hmac.digest(
                key=cipher.hmac_key,
                msg=file_in[: -2 * block_size],
                digest=hashlib.sha256,
            ),
        ), "HMAC check failed."

        # Start CTR mode
        mode = CTR(cipher, nonce)

        # Strip the salt, IV and HMAC from the ciphertext
        file_in = file_in[2 * block_size : -2 * block_size]

        file_out = encrypt_decrypt(mode.decrypt, file_in, block_size)

    # Write output file
    with open(args.output_file, "wb") as f_out:
        f_out.write(file_out)

    print(
        "\n{0} successfully completed! {1} has been stored in: {2}".format(
            "Encryption" if args.encrypt else "Decryption",
            "Ciphertext" if args.encrypt else "Plaintext",
            args.output_file,
        )
    )


if __name__ == "__main__":
    main()
