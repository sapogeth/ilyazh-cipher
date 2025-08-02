import asyncio
import platform
import hashlib
import base64
import os
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}|;:,.<>?`~"
print(f"Alphabet length: {len(ALPHABET)}")
assert len(ALPHABET) == 91 

FPS = 60

public_key = None
private_key = None
shared_secret = None

async def main():
    setup()
    while True:
        update_loop()
        await asyncio.sleep(1.0 / FPS)

def setup():
    global public_key, private_key, shared_secret

    public_key = os.urandom(32)
    private_key = os.urandom(32)
    shared_secret = os.urandom(32)

def update_loop():
    pass

def derive_initial_key(user_id, context, shared_secret):
    """Derive initial key K using SHA-256."""
    input_data = user_id.encode('utf-8') + context.encode('utf-8') + shared_secret
    return hashlib.sha256(input_data).digest()

def derive_subkey(prev_key, prev_hash):
    """Derive subkey K_i using SHA-256."""
    return hashlib.sha256(prev_key + prev_hash[:8]).digest()

def permute_alphabet(key, alphabet):
    """Permute the alphabet based on the key."""
    alphabet_list = list(alphabet)
    for i in range(len(alphabet)):
        j = (key[i % 32] + i) % (len(alphabet) - i)
        alphabet_list[i], alphabet_list[i + j] = alphabet_list[i + j], alphabet_list[i]
    return ''.join(alphabet_list)

def encrypt_block(plaintext_block, key, prev_hash):
    """Encrypt a single 16-character block."""
    if len(plaintext_block) != 16:
        plaintext_block = plaintext_block.ljust(16)
    subkey = derive_subkey(key, prev_hash)
    permuted_alphabet = permute_alphabet(subkey, ALPHABET)
    ciphertext = ""
    for j, char in enumerate(plaintext_block):
        idx = ALPHABET.index(char)
        k_idx = subkey[j % 32]
        new_idx = (idx + k_idx) % 84
        ciphertext += permuted_alphabet[new_idx]
    return ciphertext, hashlib.sha256(ciphertext.encode()).digest()[:8]

def decrypt_block(ciphertext_block, key, prev_hash):
    """Decrypt a single 16-character block."""
    if len(ciphertext_block) != 16:
        raise ValueError("Ciphertext block must be 16 characters")
    subkey = derive_subkey(key, prev_hash)
    permuted_alphabet = permute_alphabet(subkey, ALPHABET)
    plaintext = ""
    for j, char in enumerate(ciphertext_block):
        idx = permuted_alphabet.index(char)
        k_idx = subkey[j % 32]
        new_idx = (idx - k_idx) % 84
        plaintext += ALPHABET[new_idx]
    return plaintext

def encrypt(plaintext, user_id="user123", context="web3chat"):
    """Encrypt the full plaintext with step-by-step output."""
    setup()
    initial_key = derive_initial_key(user_id, context, shared_secret)
    blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]
    ciphertext = ""
    prev_hash = b'\x00' * 8
    steps = ["**Encryption Process:**\n"]
    steps.append(f"Initial Key (SHA-256): {initial_key.hex()}\n")
    steps.append(f"Shared Secret: {shared_secret.hex()}\n")
    for i, block in enumerate(blocks):
        encrypted_block, new_hash = encrypt_block(block, initial_key, prev_hash)
        ciphertext += encrypted_block
        prev_hash = new_hash
        steps.append(f"Block {i+1} (Plain): {block}\n")
        steps.append(f"Block {i+1} (Cipher): {encrypted_block}\n")
        steps.append(f"Block {i+1} Hash: {new_hash.hex()}\n")
    final_cipher = base64.b64encode(ciphertext.encode() + b"||KEM||" + os.urandom(1088)).decode()
    steps.append(f"Final Ciphertext (Base64): {final_cipher}\n")
    return "\n".join(steps), final_cipher, shared_secret  # Return shared_secret for decryption

def decrypt(ciphertext, user_id="user123", context="web3chat", shared_secret=None):
    """Decrypt the full ciphertext with step-by-step output."""
    decoded = base64.b64decode(ciphertext)
    parts = decoded.split(b"||KEM||")
    if len(parts) != 2:
        raise ValueError("Invalid ciphertext format")
    ciphertext_data = parts[0].decode()
    # Use provided shared_secret or simulate if None
    if shared_secret is None:
        initial_key = derive_initial_key(user_id, context, os.urandom(32))
    else:
        initial_key = derive_initial_key(user_id, context, shared_secret)
    blocks = [ciphertext_data[i:i+16] for i in range(0, len(ciphertext_data), 16)]
    plaintext = ""
    prev_hash = b'\x00' * 8
    steps = ["**Decryption Process:**\n"]
    steps.append(f"Initial Key (Simulated): {initial_key.hex()}\n")
    for i, block in enumerate(blocks):
        decrypted_block = decrypt_block(block, initial_key, prev_hash)
        plaintext += decrypted_block
        prev_hash = hashlib.sha256(block.encode()).digest()[:8]
        steps.append(f"Block {i+1} (Cipher): {block}\n")
        steps.append(f"Block {i+1} (Plain): {decrypted_block}\n")
    steps.append(f"Final Plaintext: {plaintext.rstrip()}\n")
    return "\n".join(steps), plaintext.rstrip()

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a welcome message when the /start command is issued."""
    await update.message.reply_text(
        "Welcome to Ilyazh-Web3E2E Demo Bot! Send any message to see it encrypted and decrypted.\n"
        "Use /help for more info."
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Send a help message."""
    await update.message.reply_text(
        "This bot demonstrates the Ilyazh-Web3E2E cipher:\n"
        "- Send a message to encrypt and decrypt it.\n"
        "- The process shows step-by-step details.\n"
        "Note: Uses simulated Kyber; for real PQ security, install pqcrypto."
    )

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle text messages and process encryption/decryption."""
    message_text = update.message.text
    enc_steps, encrypted, shared_sec = encrypt(message_text)
    dec_steps, decrypted = decrypt(encrypted, shared_secret=shared_sec)
    await update.message.reply_text(
        f"{enc_steps}\n{dec_steps}"
        f"\nVerification: {'Success' if message_text.rstrip() == decrypted else 'Failed'}"
    )

def main_bot():
    """Start the bot."""
    application = Application.builder().token('8435268741:AAGa1dwstnnuViyxCrgO_qzlT7kvo-jTx4Q').build()

    application.add_handler(CommandHandler("start", start_command))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    application.run_polling()

if platform.system() != "Emscripten":
    if __name__ == "__main__":
        asyncio.run(main_bot())
else:
    asyncio.ensure_future(main_bot())
