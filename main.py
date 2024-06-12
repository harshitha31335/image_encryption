from PIL import Image
import numpy as np
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import json
def image_to_byte_array(image_path):
    img = Image.open(image_path)
    img = img.convert('RGB')
    img_array = np.array(img)
    img_bytes = img_array.tobytes()
    return img_bytes, img.size, img.mode
def encrypt_image(byte_array, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(byte_array, AES.block_size))
    return cipher.iv + ciphertext
def save_encrypted_image(encrypted_bytes, size, mode, output_path):
    metadata = {
        'size': size,
        'mode': mode
    }
    with open(output_path, 'wb') as file:
        file.write(encrypted_bytes)
    metadata_path = output_path + '.json'
    with open(metadata_path, 'w') as metadata_file:
        json.dump(metadata, metadata_file)
def decrypt_image(encrypted_bytes, key):
    iv = encrypted_bytes[:AES.block_size]
    ciphertext = encrypted_bytes[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_bytes
def byte_array_to_image(byte_array, size, mode):
    img_array = np.frombuffer(byte_array, dtype=np.uint8).reshape(size[1], size[0], 3)
    img = Image.fromarray(img_array, mode)
    return img
def main():
    key = get_random_bytes(16)
    input_dir = 'input_images/'
    encrypted_dir = 'encrypted_images/'
    decrypted_dir = 'decrypted_images/'
    os.makedirs(encrypted_dir, exist_ok=True)
    os.makedirs(decrypted_dir, exist_ok=True)
    for image_name in os.listdir(input_dir):
        if image_name.endswith(('.jpg', '.jpeg', '.png', '.bmp')):
            input_image_path = os.path.join(input_dir, image_name)
            encrypted_image_path = os.path.join(encrypted_dir, f'{image_name}.enc')
            img_bytes, size, mode = image_to_byte_array(input_image_path)
            encrypted_bytes = encrypt_image(img_bytes, key)
            save_encrypted_image(encrypted_bytes, size, mode, encrypted_image_path)
            print(f"Image '{image_name}' encrypted and saved as '{encrypted_image_path}'")
    for encrypted_image_name in os.listdir(encrypted_dir):
        if encrypted_image_name.endswith('.enc'):
            encrypted_image_path = os.path.join(encrypted_dir, encrypted_image_name)
            decrypted_image_name = encrypted_image_name.replace('.enc', '')
            decrypted_image_path = os.path.join(decrypted_dir, decrypted_image_name)
            metadata_path = encrypted_image_path + '.json'
            with open(metadata_path, 'r') as metadata_file:
                metadata = json.load(metadata_file)
            size = tuple(metadata['size'])
            mode = metadata['mode']
            with open(encrypted_image_path, 'rb') as file:
                encrypted_bytes = file.read()
            decrypted_bytes = decrypt_image(encrypted_bytes, key)
            decrypted_img = byte_array_to_image(decrypted_bytes, size, mode)
            decrypted_img.save(decrypted_image_path)
            print(f"Image '{decrypted_image_name}' decrypted and saved as '{decrypted_image_path}'")

if __name__ == '__main__':
    main()
