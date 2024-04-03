from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ast import literal_eval 
import binascii
import subprocess
import rsa
import hashlib

def generate_rsa_encryption(message: str, public_key: rsa.PublicKey) -> str:
    """
    Generate RSA encryption using the provided message and public key.
    """
    encrypted_message = rsa.encrypt(message.encode(), public_key)

    return binascii.hexlify(encrypted_message).decode()

def write_encrypted_to_file(encrypted_message: str, file_name: str):
    """
    Write the encrypted RSA message to a file.
    """
    with open(file_name, "w") as file:
        file.write('static const char ENCRYPTED_MESSAGE[] = "' + encrypted_message + '";')

def write_private_key_to_file(private_key: rsa.PrivateKey, file_name: str):
    """
    Write the private key to a file.
    """
    with open(file_name, "wb") as file:
        file.write(private_key.save_pkcs1("PEM"))

def encrypt_aes(message: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    return binascii.hexlify(encrypted_message).decode('utf-8')

# Function to read the content of the ectf_params.h file
def read_file(file_path):
    with open(file_path, "r") as file:
        content = file.read()
    return content

def format_constant(constant):
    return f'0x{constant:0{len(hex(constant)[2:])}x}'

# Function to replace the values with the encrypted values
def replace_values(content):
    key = "sokhnandeyehabib".encode()
    bt_msg = content.find("COMPONENT_BOOT_MSG") + len("COMPONENT_BOOT_MSG") + 2
    cmp_id = content.find("COMPONENT_ID") + len("COMPONENT_ID") + 1
    at_pos_loc = content.find("ATTESTATION_LOC") + len("ATTESTATION_LOC") + 1
    at_pos_date = content.find("ATTESTATION_DATE") + len("ATTESTATION_DATE") + 1
    at_pos_cust = content.find("ATTESTATION_CUSTOMER") + len("ATTESTATION_CUSTOMER") + 1
    endif_pos= content.find("#endif") +len("#endif") +1
    encrypted_value_loc = encrypt_aes(content[at_pos_loc:at_pos_date - 26], key)
    encrypted_value_date = encrypt_aes(content[at_pos_date:at_pos_cust - 29], key)
    encrypted_value_cust = encrypt_aes(content[at_pos_cust:endif_pos - 7], key)

    content = (
        f"{content[:at_pos_loc - 15]}{encrypted_value_loc}{content[at_pos_loc + 15:]}"
        f"{content[:at_pos_date - 15]}{encrypted_value_date}{content[at_pos_date + 15:]}"
        f"{content[:at_pos_cust - 15]}{encrypted_value_cust}{content[at_pos_cust + 15:]}"
    )
    hex_comp_id = format_constant(literal_eval(content[cmp_id:bt_msg-27]))
    new_file_content = (
        "#ifndef __ECTF_PARAMS__\n"
        "#define __ECTF_PARAMS__\n"
        f"#define COMPONENT_ID {hex_comp_id}\n"
        f"#define COMPONENT_BOOT_MSG \"{content[bt_msg:at_pos_loc-26]}\"\n"
        f"#define ATTESTATION_LOC \"{encrypted_value_loc}\"\n"
        f"#define ATTESTATION_DATE \"{encrypted_value_date}\"\n"
        f"#define ATTESTATION_CUSTOMER \"{encrypted_value_cust}\"\n"
        "#endif\n"
    )
    return new_file_content

# Function to write the updated content to a new file
def write_file(content, file_path):
    with open(file_path, "w") as file:
        file.write(content)
        file.close()



# M
# Read the content of the ectf_params.h file
file_path = "inc/ectf_params.h"
content = read_file(file_path)

# Replace the values with the encrypted values
new_content = replace_values(content)

# Write the updated content to a new file
new_file_path = "new_ectf_params.h"
write_file(new_content, new_file_path)

# Generate a 2048-bit RSA public and private key pair
(public_key, private_key) = rsa.newkeys(2048)

# Encrypt the given string "colombeAcademy-Taskforce" using the RSA public key
encrypted_message = generate_rsa_encryption("colombeAcademy-TaskforcecolombeAcademy-Taskforce", public_key)

# Write the encrypted RSA message to the file `global_secrets.h`
write_encrypted_to_file(encrypted_message, "inc/global_secrets.h")

# Write the private key to the file `private_key.pem`
write_private_key_to_file(private_key, "../walkthrough/colombehsn.pem")

command = "mv new_ectf_params.h inc/ectf_params.h"
# Run the command
subprocess.Popen(command, shell=True)