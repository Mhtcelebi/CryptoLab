#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CryptoLab - Production-grade cryptographic CLI toolkit.
Standard library only. Cross-platform (Windows / Linux).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import sys


# ---------------------------------------------------------------------------
# Localization
# ---------------------------------------------------------------------------

LANG: dict[str, dict[str, str]] = {
    "tr": {
        "language_prompt": "Dil seçin / Select language:\n  1. Türkçe\n  2. English\n\nSeçiminiz: ",
        "invalid_language": "Geçersiz seçim. 1 veya 2 girin.",
        "press_enter": "\nDevam etmek için Enter'a basın...",
        "goodbye": "CryptoLab kapatılıyor. Güle güle!",
        "interrupted": "\n\nİşlem iptal edildi. CryptoLab kapatılıyor.",
        "back": "0. Geri",
        "exit": "0. Çıkış",
        "invalid_choice": "Geçersiz seçim. Lütfen tekrar deneyin.",
        "empty_input": "Boş giriş kabul edilmiyor.",
        "input_error": "Giriş hatası: {error}",
        "operation_failed": "İşlem başarısız: {error}",
        "main_menu_title": "═══ ANA MENÜ ═══",
        "main_1": "1. Klasik & Antik Şifreler",
        "main_2": "2. Kodlama & Taban Dönüşümü",
        "main_3": "3. Modern Hash Fonksiyonları",
        "cat1_title": "═══ KLASİK & ANTİK ŞİFRELER ═══",
        "cat1_1": "1. Sezar Şifresi (Caesar)",
        "cat1_2": "2. Vigenère Şifresi",
        "cat1_3": "3. Affine Şifresi",
        "cat1_4": "4. Atbash Şifresi",
        "cat1_5": "5. ROT13",
        "cat1_6": "6. Rail Fence Şifresi",
        "cat2_title": "═══ KODLAMA & TABAN DÖNÜŞÜMÜ ═══",
        "cat2_1": "1. Base16 / Hexadecimal",
        "cat2_2": "2. Base32",
        "cat2_3": "3. Base64",
        "cat2_4": "4. Base85 / Ascii85",
        "cat2_5": "5. Binary (İkili)",
        "cat3_title": "═══ MODERN HASH FONKSİYONLARI ═══",
        "cat3_1": "1. MD5",
        "cat3_2": "2. SHA-1",
        "cat3_3": "3. SHA-224",
        "cat3_4": "4. SHA-256",
        "cat3_5": "5. SHA-384",
        "cat3_6": "6. SHA-512",
        "cat3_7": "7. SHA3-224",
        "cat3_8": "8. SHA3-256",
        "cat3_9": "9. SHA3-384",
        "cat3_10": "10. SHA3-512",
        "op_title": "═══ İŞLEM SEÇİN ═══",
        "op_encrypt": "1. Şifrele (Encrypt)",
        "op_decrypt": "2. Deşifrele (Decrypt)",
        "op_encode": "1. Kodla (Encode)",
        "op_decode": "2. Çöz (Decode)",
        "op_generate": "1. Hash Oluştur",
        "op_verify": "2. Hash Doğrula",
        "prompt_text": "Metin girin: ",
        "prompt_ciphertext": "Şifreli metin girin: ",
        "prompt_shift": "Kaydırma anahtarı (tam sayı) girin: ",
        "prompt_vigenere_key": "Vigenère anahtarı girin: ",
        "prompt_affine_a": "'a' değerini girin (1-25, 26 ile aralarında asal olmalı): ",
        "prompt_affine_b": "'b' değerini girin (0-25): ",
        "prompt_rails": "Ray (rail) sayısını girin (2 ve üzeri): ",
        "prompt_hash_text": "Hash'lenecek metin girin: ",
        "prompt_hash_verify_text": "Doğrulanacak metin girin: ",
        "prompt_hash_value": "Karşılaştırılacak hash değerini girin: ",
        "prompt_encoded": "Kodlanmış veri girin: ",
        "result_title": "═══ SONUÇ ═══",
        "result_encrypted": "Şifreli metin: {result}",
        "result_decrypted": "Deşifrelenmiş metin: {result}",
        "result_encoded": "Kodlanmış veri: {result}",
        "result_decoded": "Çözülmüş metin: {result}",
        "result_hash": "Hash: {result}",
        "hash_match": "✓ Hash EŞLEŞTİ — metin doğrulandı.",
        "hash_no_match": "✗ Hash EŞLEŞMEDİ — metin doğrulanamadı.",
        "err_not_integer": "Geçersiz tam sayı.",
        "err_shift_zero": "Kaydırma anahtarı 0 olamaz.",
        "err_vigenere_key": "Anahtar en az bir harf içermelidir.",
        "err_affine_a": "'a' değeri 26 ile aralarında asal olmalıdır (gcd(a,26)=1).",
        "err_affine_range": "'a' 1-25 arasında, 'b' 0-25 arasında olmalıdır.",
        "err_rails": "Ray sayısı en az 2 olmalıdır.",
        "err_no_alpha": "Metin en az bir alfabetik karakter içermelidir.",
        "err_hex": "Geçersiz hexadecimal veri.",
        "err_base32": "Geçersiz Base32 verisi.",
        "err_base64": "Geçersiz Base64 verisi.",
        "err_base85": "Geçersiz Base85/Ascii85 verisi.",
        "err_binary": "Geçersiz binary veri (yalnızca 0 ve 1 kullanın).",
        "err_binary_length": "Binary uzunluğu 8'in katı olmalıdır.",
        "err_decode_utf8": "Çözülen veri geçerli UTF-8 metni değil.",
        "err_hash_unsupported": "Desteklenmeyen hash algoritması.",
    },
    "en": {
        "language_prompt": "Select language / Dil seçin:\n  1. Türkçe\n  2. English\n\nYour choice: ",
        "invalid_language": "Invalid choice. Enter 1 or 2.",
        "press_enter": "\nPress Enter to continue...",
        "goodbye": "Closing CryptoLab. Goodbye!",
        "interrupted": "\n\nOperation cancelled. Closing CryptoLab.",
        "back": "0. Back",
        "exit": "0. Exit",
        "invalid_choice": "Invalid choice. Please try again.",
        "empty_input": "Empty input is not allowed.",
        "input_error": "Input error: {error}",
        "operation_failed": "Operation failed: {error}",
        "main_menu_title": "═══ MAIN MENU ═══",
        "main_1": "1. Classic & Antique Ciphers",
        "main_2": "2. Encoding & Base Conversion",
        "main_3": "3. Modern Hash Functions",
        "cat1_title": "═══ CLASSIC & ANTIQUE CIPHERS ═══",
        "cat1_1": "1. Caesar Cipher",
        "cat1_2": "2. Vigenère Cipher",
        "cat1_3": "3. Affine Cipher",
        "cat1_4": "4. Atbash Cipher",
        "cat1_5": "5. ROT13",
        "cat1_6": "6. Rail Fence Cipher",
        "cat2_title": "═══ ENCODING & BASE CONVERSION ═══",
        "cat2_1": "1. Base16 / Hexadecimal",
        "cat2_2": "2. Base32",
        "cat2_3": "3. Base64",
        "cat2_4": "4. Base85 / Ascii85",
        "cat2_5": "5. Binary",
        "cat3_title": "═══ MODERN HASH FUNCTIONS ═══",
        "cat3_1": "1. MD5",
        "cat3_2": "2. SHA-1",
        "cat3_3": "3. SHA-224",
        "cat3_4": "4. SHA-256",
        "cat3_5": "5. SHA-384",
        "cat3_6": "6. SHA-512",
        "cat3_7": "7. SHA3-224",
        "cat3_8": "8. SHA3-256",
        "cat3_9": "9. SHA3-384",
        "cat3_10": "10. SHA3-512",
        "op_title": "═══ SELECT OPERATION ═══",
        "op_encrypt": "1. Encrypt",
        "op_decrypt": "2. Decrypt",
        "op_encode": "1. Encode",
        "op_decode": "2. Decode",
        "op_generate": "1. Generate Hash",
        "op_verify": "2. Verify Hash",
        "prompt_text": "Enter text: ",
        "prompt_ciphertext": "Enter ciphertext: ",
        "prompt_shift": "Enter shift key (integer): ",
        "prompt_vigenere_key": "Enter Vigenère key: ",
        "prompt_affine_a": "Enter 'a' value (1-25, must be coprime with 26): ",
        "prompt_affine_b": "Enter 'b' value (0-25): ",
        "prompt_rails": "Enter number of rails (2 or more): ",
        "prompt_hash_text": "Enter text to hash: ",
        "prompt_hash_verify_text": "Enter text to verify: ",
        "prompt_hash_value": "Enter hash value to compare: ",
        "prompt_encoded": "Enter encoded data: ",
        "result_title": "═══ RESULT ═══",
        "result_encrypted": "Ciphertext: {result}",
        "result_decrypted": "Plaintext: {result}",
        "result_encoded": "Encoded data: {result}",
        "result_decoded": "Decoded text: {result}",
        "result_hash": "Hash: {result}",
        "hash_match": "✓ Hash MATCHED — text verified.",
        "hash_no_match": "✗ Hash DID NOT MATCH — text not verified.",
        "err_not_integer": "Invalid integer.",
        "err_shift_zero": "Shift key cannot be zero.",
        "err_vigenere_key": "Key must contain at least one letter.",
        "err_affine_a": "'a' must be coprime with 26 (gcd(a,26)=1).",
        "err_affine_range": "'a' must be 1-25 and 'b' must be 0-25.",
        "err_rails": "Number of rails must be at least 2.",
        "err_no_alpha": "Text must contain at least one alphabetic character.",
        "err_hex": "Invalid hexadecimal data.",
        "err_base32": "Invalid Base32 data.",
        "err_base64": "Invalid Base64 data.",
        "err_base85": "Invalid Base85/Ascii85 data.",
        "err_binary": "Invalid binary data (use only 0 and 1).",
        "err_binary_length": "Binary length must be a multiple of 8.",
        "err_decode_utf8": "Decoded data is not valid UTF-8 text.",
        "err_hash_unsupported": "Unsupported hash algorithm.",
    },
}


BANNER = r"""
   ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗ ██╗      █████╗ ██████╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗██║     ██╔══██╗██╔══██╗
  ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║██║     ███████║██████╔╝
  ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║██║     ██╔══██║██╔══██╗
  ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝███████╗██║  ██║██████╔╝
   ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═════╝
                    Production Cryptographic Toolkit  v1.0
"""


# ---------------------------------------------------------------------------
# Cross-platform utilities
# ---------------------------------------------------------------------------

def clear_screen() -> None:
    """Clear terminal screen (Windows: cls, Linux: clear)."""
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except OSError:
        pass


def utf8_encode(text: str) -> bytes:
    """Encode string to UTF-8 bytes."""
    return text.encode("utf-8")


def utf8_decode(data: bytes) -> str:
    """Decode UTF-8 bytes to string."""
    return data.decode("utf-8")


def pause(s: dict[str, str]) -> None:
    """Wait for user acknowledgment."""
    try:
        input(s["press_enter"])
    except (KeyboardInterrupt, EOFError):
        raise KeyboardInterrupt


def read_line(prompt: str, *, allow_empty: bool = False) -> str | None:
    """
    Read a line of input safely.
    Returns None on empty disallowed input or read failure.
    Raises KeyboardInterrupt on Ctrl+C / EOF when appropriate.
    """
    try:
        value = input(prompt)
    except KeyboardInterrupt:
        raise
    except EOFError:
        raise KeyboardInterrupt
    except Exception:
        return None

    value = value.strip()
    if not value and not allow_empty:
        return None
    return value


def parse_int(raw: str, s: dict[str, str]) -> int | None:
    """Parse integer from a non-empty string."""
    try:
        return int(raw, 10)
    except ValueError:
        print(s["err_not_integer"])
        return None


def _is_latin_alpha(char: str) -> bool:
    """True only for ASCII A-Z / a-z (classic cipher alphabet)."""
    return ("A" <= char <= "Z") or ("a" <= char <= "z")


def show_error(s: dict[str, str], message: str) -> None:
    """Display a user-friendly error."""
    print(f"\n[!] {message}")


def show_result(s: dict[str, str], template_key: str, result: str) -> None:
    """Display operation result."""
    print(f"\n{s['result_title']}")
    print(s[template_key].format(result=result))


# ---------------------------------------------------------------------------
# Classic cipher implementations
# ---------------------------------------------------------------------------

def _shift_char(char: str, shift: int) -> str:
    """Shift a single alphabetic character by shift mod 26, preserving case."""
    if "A" <= char <= "Z":
        base = ord("A")
        return chr((ord(char) - base + shift) % 26 + base)
    if "a" <= char <= "z":
        base = ord("a")
        return chr((ord(char) - base + shift) % 26 + base)
    return char


def caesar_cipher(text: str, shift: int, *, decrypt: bool = False) -> str:
    """Caesar cipher with dynamic key; preserves case and non-alpha chars."""
    effective_shift = (-shift if decrypt else shift) % 26
    return "".join(_shift_char(c, effective_shift) for c in text)


def _vigenere_key_stream(text: str, key: str) -> list[int]:
    """Build shift values from repeating case-insensitive key."""
    key_shifts = []
    for ch in key:
        if _is_latin_alpha(ch):
            key_shifts.append(ord(ch.upper()) - ord("A"))
    if not key_shifts:
        raise ValueError("empty_key")
    stream: list[int] = []
    ki = 0
    for ch in text:
        if _is_latin_alpha(ch):
            stream.append(key_shifts[ki % len(key_shifts)])
            ki += 1
    return stream


def vigenere_cipher(text: str, key: str, *, decrypt: bool = False) -> str:
    """Vigenère cipher with string key; case-insensitive key, preserves text case."""
    if not any(_is_latin_alpha(ch) for ch in key):
        raise ValueError("empty_key")

    shifts = _vigenere_key_stream(text, key)
    si = 0
    result: list[str] = []
    for ch in text:
        if _is_latin_alpha(ch):
            shift = shifts[si]
            if decrypt:
                shift = -shift
            result.append(_shift_char(ch, shift))
            si += 1
        else:
            result.append(ch)
    return "".join(result)


def _mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean algorithm for modular multiplicative inverse."""
    if math.gcd(a, m) != 1:
        raise ValueError("no_inverse")
    t, new_t = 0, 1
    r, new_r = m, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r != 1:
        raise ValueError("no_inverse")
    if t < 0:
        t += m
    return t


def affine_cipher(text: str, a: int, b: int, *, decrypt: bool = False) -> str:
    """
    Affine cipher E(x) = (ax + b) mod 26.
    Decryption requires modular inverse of a mod 26.
    """
    if not (1 <= a <= 25 and 0 <= b <= 25):
        raise ValueError("range")
    if math.gcd(a, 26) != 1:
        raise ValueError("no_inverse")

    if decrypt:
        a_inv = _mod_inverse(a, 26)
        result: list[str] = []
        for ch in text:
            if _is_latin_alpha(ch):
                base = ord("A") if ch.isupper() else ord("a")
                y = ord(ch) - base
                x = (a_inv * (y - b)) % 26
                result.append(chr(x + base))
            else:
                result.append(ch)
        return "".join(result)

    result = []
    for ch in text:
        if _is_latin_alpha(ch):
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            y = (a * x + b) % 26
            result.append(chr(y + base))
        else:
            result.append(ch)
    return "".join(result)


def atbash_cipher(text: str) -> str:
    """Atbash cipher — alphabet reversal (self-inverse)."""
    result: list[str] = []
    for ch in text:
        if "A" <= ch <= "Z":
            result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        elif "a" <= ch <= "z":
            result.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            result.append(ch)
    return "".join(result)


def rot13_cipher(text: str) -> str:
    """ROT13 — fixed 13-character Caesar shift (self-inverse)."""
    return caesar_cipher(text, 13, decrypt=False)


def rail_fence_cipher(text: str, rails: int, *, decrypt: bool = False) -> str:
    """Rail Fence (zig-zag) transposition cipher."""
    if rails < 2:
        raise ValueError("rails")

    if not decrypt:
        fence: list[list[str]] = [[] for _ in range(rails)]
        rail = 0
        direction = 1
        for ch in text:
            fence[rail].append(ch)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        return "".join("".join(row) for row in fence)

    n = len(text)
    if n == 0:
        return ""

    pattern: list[int] = []
    rail = 0
    direction = 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    counts = [0] * rails
    for r in pattern:
        counts[r] += 1

    rows: list[list[str]] = []
    idx = 0
    for count in counts:
        rows.append(list(text[idx : idx + count]))
        idx += count

    result: list[str] = []
    row_pos = [0] * rails
    for r in pattern:
        result.append(rows[r][row_pos[r]])
        row_pos[r] += 1
    return "".join(result)


# ---------------------------------------------------------------------------
# Encoding & base conversion
# ---------------------------------------------------------------------------

def encode_base16(text: str) -> str:
    """Encode text to hexadecimal (Base16)."""
    return binascii.hexlify(utf8_encode(text)).decode("ascii").upper()


def decode_base16(data: str) -> str:
    """Decode hexadecimal (Base16) to UTF-8 text."""
    cleaned = "".join(data.split()).replace(":", "").replace("-", "")
    if cleaned.lower().startswith("0x"):
        cleaned = cleaned[2:]
    if len(cleaned) % 2 != 0:
        raise ValueError("hex")
    try:
        raw = binascii.unhexlify(cleaned)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("hex") from exc
    try:
        return utf8_decode(raw)
    except UnicodeDecodeError as exc:
        raise ValueError("utf8") from exc


def encode_base32(text: str) -> str:
    """Encode text to Base32."""
    return base64.b32encode(utf8_encode(text)).decode("ascii")


def decode_base32(data: str) -> str:
    """Decode Base32 to UTF-8 text."""
    cleaned = data.strip().replace(" ", "").upper()
    padding = (-len(cleaned)) % 8
    cleaned += "=" * padding
    try:
        raw = base64.b32decode(cleaned, casefold=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base32") from exc
    try:
        return utf8_decode(raw)
    except UnicodeDecodeError as exc:
        raise ValueError("utf8") from exc


def encode_base64(text: str) -> str:
    """Encode text to Base64."""
    return base64.b64encode(utf8_encode(text)).decode("ascii")


def decode_base64(data: str) -> str:
    """Decode Base64 to UTF-8 text."""
    cleaned = data.strip().replace("\n", "").replace("\r", "")
    padding = (-len(cleaned)) % 4
    cleaned += "=" * padding
    try:
        raw = base64.b64decode(cleaned, validate=False)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base64") from exc
    try:
        return utf8_decode(raw)
    except UnicodeDecodeError as exc:
        raise ValueError("utf8") from exc


def encode_base85(text: str) -> str:
    """Encode text to Ascii85 (Base85)."""
    return base64.a85encode(utf8_encode(text), adobe=False).decode("ascii")


def decode_base85(data: str) -> str:
    """Decode Ascii85 (Base85) to UTF-8 text."""
    cleaned = data.strip().encode("ascii")
    try:
        raw = base64.a85decode(cleaned, adobe=False, ignorechars=b" \t\n\r")
    except (binascii.Error, ValueError) as exc:
        raise ValueError("base85") from exc
    try:
        return utf8_decode(raw)
    except UnicodeDecodeError as exc:
        raise ValueError("utf8") from exc


def encode_binary(text: str) -> str:
    """Convert text to space-separated 8-bit binary representation."""
    bits = " ".join(format(byte, "08b") for byte in utf8_encode(text))
    return bits


def decode_binary(data: str) -> str:
    """Convert binary string (with or without whitespace) back to text."""
    cleaned = "".join(data.split())
    if not cleaned:
        raise ValueError("binary")
    if any(ch not in "01" for ch in cleaned):
        raise ValueError("binary")
    if len(cleaned) % 8 != 0:
        raise ValueError("binary_length")

    byte_values = bytearray()
    for i in range(0, len(cleaned), 8):
        byte_values.append(int(cleaned[i : i + 8], 2))

    try:
        return utf8_decode(bytes(byte_values))
    except UnicodeDecodeError as exc:
        raise ValueError("utf8") from exc


# ---------------------------------------------------------------------------
# Hash functions
# ---------------------------------------------------------------------------

HASH_ALGORITHMS: dict[str, str] = {
    "1": "md5",
    "2": "sha1",
    "3": "sha224",
    "4": "sha256",
    "5": "sha384",
    "6": "sha512",
    "7": "sha3_224",
    "8": "sha3_256",
    "9": "sha3_384",
    "10": "sha3_512",
}


def compute_hash(text: str, algorithm: str) -> str:
    """Compute hexadecimal hash digest for text using hashlib."""
    if algorithm not in hashlib.algorithms_available:
        raise ValueError("unsupported")
    digest = hashlib.new(algorithm, utf8_encode(text))
    return digest.hexdigest()


def verify_hash(text: str, expected: str, algorithm: str) -> bool:
    """Compare computed hash with expected value (case-insensitive)."""
    computed = compute_hash(text, algorithm)
    return computed.lower() == expected.strip().lower()


# ---------------------------------------------------------------------------
# Menu handlers
# ---------------------------------------------------------------------------

def select_language() -> dict[str, str]:
    """Prompt for TR/EN language selection."""
    while True:
        clear_screen()
        print(BANNER)
        try:
            choice = input(LANG["en"]["language_prompt"]).strip()
        except (KeyboardInterrupt, EOFError):
            raise KeyboardInterrupt

        if choice == "1":
            return LANG["tr"]
        if choice == "2":
            return LANG["en"]
        print(LANG["en"]["invalid_language"])
        try:
            input(LANG["en"]["press_enter"])
        except (KeyboardInterrupt, EOFError):
            raise KeyboardInterrupt


def menu_encrypt_decrypt(
    s: dict[str, str],
    encrypt_fn,
    decrypt_fn,
    *,
    needs_extra_input_encrypt=None,
    needs_extra_input_decrypt=None,
) -> None:
    """Generic encrypt/decrypt operation flow."""
    clear_screen()
    print(s["op_title"])
    print(s["op_encrypt"])
    print(s["op_decrypt"])
    print(s["back"])

    try:
        choice = read_line("\n> ")
    except KeyboardInterrupt:
        raise

    if choice is None or choice == "0":
        return

    if choice == "1":
        text = read_line(s["prompt_text"])
        if text is None:
            show_error(s, s["empty_input"])
            pause(s)
            return
        extra = None
        if needs_extra_input_encrypt:
            extra = needs_extra_input_encrypt(s)
            if extra is None:
                pause(s)
                return
        try:
            result = encrypt_fn(text, extra) if extra is not None else encrypt_fn(text)
            show_result(s, "result_encrypted", result)
        except ValueError as exc:
            show_error(s, _map_cipher_error(s, exc))
        except Exception as exc:
            show_error(s, s["operation_failed"].format(error=str(exc)))
        pause(s)
        return

    if choice == "2":
        text = read_line(s["prompt_ciphertext"])
        if text is None:
            show_error(s, s["empty_input"])
            pause(s)
            return
        extra = None
        if needs_extra_input_decrypt:
            extra = needs_extra_input_decrypt(s)
            if extra is None:
                pause(s)
                return
        try:
            result = decrypt_fn(text, extra) if extra is not None else decrypt_fn(text)
            show_result(s, "result_decrypted", result)
        except ValueError as exc:
            show_error(s, _map_cipher_error(s, exc))
        except Exception as exc:
            show_error(s, s["operation_failed"].format(error=str(exc)))
        pause(s)
        return

    show_error(s, s["invalid_choice"])
    pause(s)


def _map_cipher_error(s: dict[str, str], exc: ValueError) -> str:
    """Map internal ValueError codes to localized messages."""
    code = str(exc)
    mapping = {
        "empty_key": s["err_vigenere_key"],
        "no_inverse": s["err_affine_a"],
        "range": s["err_affine_range"],
        "rails": s["err_rails"],
        "hex": s["err_hex"],
        "base32": s["err_base32"],
        "base64": s["err_base64"],
        "base85": s["err_base85"],
        "binary": s["err_binary"],
        "binary_length": s["err_binary_length"],
        "utf8": s["err_decode_utf8"],
        "unsupported": s["err_hash_unsupported"],
    }
    return mapping.get(code, s["operation_failed"].format(error=code))


def _prompt_caesar_shift(s: dict[str, str]) -> int | None:
    raw = read_line(s["prompt_shift"])
    if raw is None:
        show_error(s, s["empty_input"])
        return None
    return parse_int(raw, s)


def _prompt_vigenere_key(s: dict[str, str]) -> str | None:
    key = read_line(s["prompt_vigenere_key"])
    if key is None:
        show_error(s, s["empty_input"])
        return None
    if not any(_is_latin_alpha(ch) for ch in key):
        show_error(s, s["err_vigenere_key"])
        return None
    return key


def _prompt_affine_params(s: dict[str, str]) -> tuple[int, int] | None:
    raw_a = read_line(s["prompt_affine_a"])
    if raw_a is None:
        show_error(s, s["empty_input"])
        return None
    a = parse_int(raw_a, s)
    if a is None:
        return None
    raw_b = read_line(s["prompt_affine_b"])
    if raw_b is None:
        show_error(s, s["empty_input"])
        return None
    b = parse_int(raw_b, s)
    if b is None:
        return None
    if not (1 <= a <= 25 and 0 <= b <= 25):
        show_error(s, s["err_affine_range"])
        return None
    if math.gcd(a, 26) != 1:
        show_error(s, s["err_affine_a"])
        return None
    return a, b


def _prompt_rails(s: dict[str, str]) -> int | None:
    raw = read_line(s["prompt_rails"])
    if raw is None:
        show_error(s, s["empty_input"])
        return None
    rails = parse_int(raw, s)
    if rails is None:
        return None
    if rails < 2:
        show_error(s, s["err_rails"])
        return None
    return rails


def handle_caesar(s: dict[str, str]) -> None:
    def get_shift(_s):
        return _prompt_caesar_shift(_s)

    def enc(text, shift):
        return caesar_cipher(text, shift, decrypt=False)

    def dec(text, shift):
        return caesar_cipher(text, shift, decrypt=True)

    menu_encrypt_decrypt(
        s, enc, dec,
        needs_extra_input_encrypt=get_shift,
        needs_extra_input_decrypt=get_shift,
    )


def handle_vigenere(s: dict[str, str]) -> None:
    def get_key(_s):
        return _prompt_vigenere_key(_s)

    def enc(text, key):
        return vigenere_cipher(text, key, decrypt=False)

    def dec(text, key):
        return vigenere_cipher(text, key, decrypt=True)

    menu_encrypt_decrypt(
        s, enc, dec,
        needs_extra_input_encrypt=get_key,
        needs_extra_input_decrypt=get_key,
    )


def handle_affine(s: dict[str, str]) -> None:
    def get_params(_s):
        return _prompt_affine_params(_s)

    def enc(text, params):
        a, b = params
        return affine_cipher(text, a, b, decrypt=False)

    def dec(text, params):
        a, b = params
        return affine_cipher(text, a, b, decrypt=True)

    menu_encrypt_decrypt(
        s, enc, dec,
        needs_extra_input_encrypt=get_params,
        needs_extra_input_decrypt=get_params,
    )


def handle_atbash(s: dict[str, str]) -> None:
    def enc(text, _extra=None):
        return atbash_cipher(text)

    def dec(text, _extra=None):
        return atbash_cipher(text)

    menu_encrypt_decrypt(s, enc, dec)


def handle_rot13(s: dict[str, str]) -> None:
    def enc(text, _extra=None):
        return rot13_cipher(text)

    def dec(text, _extra=None):
        return rot13_cipher(text)

    menu_encrypt_decrypt(s, enc, dec)


def handle_rail_fence(s: dict[str, str]) -> None:
    def get_rails(_s):
        return _prompt_rails(_s)

    def enc(text, rails):
        return rail_fence_cipher(text, rails, decrypt=False)

    def dec(text, rails):
        return rail_fence_cipher(text, rails, decrypt=True)

    menu_encrypt_decrypt(
        s, enc, dec,
        needs_extra_input_encrypt=get_rails,
        needs_extra_input_decrypt=get_rails,
    )


def menu_encode_decode(
    s: dict[str, str],
    encode_fn,
    decode_fn,
) -> None:
    """Generic encode/decode operation flow."""
    clear_screen()
    print(s["op_title"])
    print(s["op_encode"])
    print(s["op_decode"])
    print(s["back"])

    try:
        choice = read_line("\n> ")
    except KeyboardInterrupt:
        raise

    if choice is None or choice == "0":
        return

    if choice == "1":
        text = read_line(s["prompt_text"])
        if text is None:
            show_error(s, s["empty_input"])
            pause(s)
            return
        try:
            result = encode_fn(text)
            show_result(s, "result_encoded", result)
        except Exception as exc:
            show_error(s, s["operation_failed"].format(error=str(exc)))
        pause(s)
        return

    if choice == "2":
        data = read_line(s["prompt_encoded"])
        if data is None:
            show_error(s, s["empty_input"])
            pause(s)
            return
        try:
            result = decode_fn(data)
            show_result(s, "result_decoded", result)
        except ValueError as exc:
            show_error(s, _map_cipher_error(s, exc))
        except Exception as exc:
            show_error(s, s["operation_failed"].format(error=str(exc)))
        pause(s)
        return

    show_error(s, s["invalid_choice"])
    pause(s)


def handle_hash(s: dict[str, str], algorithm: str) -> None:
    """Generate or verify hash for a selected algorithm."""
    clear_screen()
    print(s["op_title"])
    print(s["op_generate"])
    print(s["op_verify"])
    print(s["back"])

    try:
        choice = read_line("\n> ")
    except KeyboardInterrupt:
        raise

    if choice is None or choice == "0":
        return

    if choice == "1":
        text = read_line(s["prompt_hash_text"])
        if text is None:
            show_error(s, s["empty_input"])
            pause(s)
            return
        try:
            result = compute_hash(text, algorithm)
            show_result(s, "result_hash", result)
        except ValueError as exc:
            show_error(s, _map_cipher_error(s, exc))
        except Exception as exc:
            show_error(s, s["operation_failed"].format(error=str(exc)))
        pause(s)
        return

    if choice == "2":
        text = read_line(s["prompt_hash_verify_text"])
        if text is None:
            show_error(s, s["empty_input"])
            pause(s)
            return
        expected = read_line(s["prompt_hash_value"])
        if expected is None:
            show_error(s, s["empty_input"])
            pause(s)
            return
        try:
            matched = verify_hash(text, expected, algorithm)
            print(f"\n{s['result_title']}")
            print(s["hash_match"] if matched else s["hash_no_match"])
        except ValueError as exc:
            show_error(s, _map_cipher_error(s, exc))
        except Exception as exc:
            show_error(s, s["operation_failed"].format(error=str(exc)))
        pause(s)
        return

    show_error(s, s["invalid_choice"])
    pause(s)


def category_classic_ciphers(s: dict[str, str]) -> None:
    """Classic & antique ciphers submenu."""
    handlers = {
        "1": handle_caesar,
        "2": handle_vigenere,
        "3": handle_affine,
        "4": handle_atbash,
        "5": handle_rot13,
        "6": handle_rail_fence,
    }
    while True:
        clear_screen()
        print(s["cat1_title"])
        print(s["cat1_1"])
        print(s["cat1_2"])
        print(s["cat1_3"])
        print(s["cat1_4"])
        print(s["cat1_5"])
        print(s["cat1_6"])
        print(s["back"])

        try:
            choice = read_line("\n> ")
        except KeyboardInterrupt:
            raise

        if choice is None or choice == "0":
            return

        handler = handlers.get(choice)
        if handler:
            try:
                handler(s)
            except KeyboardInterrupt:
                raise
        else:
            show_error(s, s["invalid_choice"])
            pause(s)


def category_encoding(s: dict[str, str]) -> None:
    """Encoding & base conversion submenu."""
    handlers = {
        "1": lambda st: menu_encode_decode(st, encode_base16, decode_base16),
        "2": lambda st: menu_encode_decode(st, encode_base32, decode_base32),
        "3": lambda st: menu_encode_decode(st, encode_base64, decode_base64),
        "4": lambda st: menu_encode_decode(st, encode_base85, decode_base85),
        "5": lambda st: menu_encode_decode(st, encode_binary, decode_binary),
    }
    while True:
        clear_screen()
        print(s["cat2_title"])
        print(s["cat2_1"])
        print(s["cat2_2"])
        print(s["cat2_3"])
        print(s["cat2_4"])
        print(s["cat2_5"])
        print(s["back"])

        try:
            choice = read_line("\n> ")
        except KeyboardInterrupt:
            raise

        if choice is None or choice == "0":
            return

        handler = handlers.get(choice)
        if handler:
            try:
                handler(s)
            except KeyboardInterrupt:
                raise
        else:
            show_error(s, s["invalid_choice"])
            pause(s)


def category_hashes(s: dict[str, str]) -> None:
    """Modern hash functions submenu."""
    while True:
        clear_screen()
        print(s["cat3_title"])
        print(s["cat3_1"])
        print(s["cat3_2"])
        print(s["cat3_3"])
        print(s["cat3_4"])
        print(s["cat3_5"])
        print(s["cat3_6"])
        print(s["cat3_7"])
        print(s["cat3_8"])
        print(s["cat3_9"])
        print(s["cat3_10"])
        print(s["back"])

        try:
            choice = read_line("\n> ")
        except KeyboardInterrupt:
            raise

        if choice is None or choice == "0":
            return

        algorithm = HASH_ALGORITHMS.get(choice)
        if algorithm:
            try:
                handle_hash(s, algorithm)
            except KeyboardInterrupt:
                raise
        else:
            show_error(s, s["invalid_choice"])
            pause(s)


def main_menu(s: dict[str, str]) -> None:
    """Application main menu loop."""
    categories = {
        "1": category_classic_ciphers,
        "2": category_encoding,
        "3": category_hashes,
    }
    while True:
        clear_screen()
        print(BANNER)
        print(s["main_menu_title"])
        print(s["main_1"])
        print(s["main_2"])
        print(s["main_3"])
        print(s["exit"])

        try:
            choice = read_line("\n> ")
        except KeyboardInterrupt:
            raise

        if choice is None:
            show_error(s, s["invalid_choice"])
            pause(s)
            continue

        if choice == "0":
            clear_screen()
            print(s["goodbye"])
            return

        handler = categories.get(choice)
        if handler:
            try:
                handler(s)
            except KeyboardInterrupt:
                raise
        else:
            show_error(s, s["invalid_choice"])
            pause(s)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Bootstrap CryptoLab with UTF-8 enforcement and graceful shutdown."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass
    if hasattr(sys.stdin, "reconfigure"):
        try:
            sys.stdin.reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            pass

    strings: dict[str, str] | None = None
    try:
        strings = select_language()
        main_menu(strings)
    except KeyboardInterrupt:
        clear_screen()
        msg = strings["interrupted"] if strings else LANG["en"]["interrupted"]
        print(msg)
        sys.exit(0)
    except Exception as exc:
        clear_screen()
        err_msg = (
            strings["operation_failed"].format(error=str(exc))
            if strings
            else f"Fatal error: {exc}"
        )
        print(err_msg)
        sys.exit(1)


if __name__ == "__main__":
    main()
