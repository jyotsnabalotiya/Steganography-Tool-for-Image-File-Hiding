#!/usr/bin/env python3
"""
LSB Steganography Tool (PNG/BMP). Embed/extract text or files with optional password.
Usage examples:
  python3 stego.py embed-text -i samples/cover.png -o out_text_stego.png -m "Hello" --password "pwd"
  python3 stego.py embed-file -i samples/cover.png -o out_file.png -f secret.txt
  python3 stego.py extract -i out_text_stego.png --password "pwd"
"""
import argparse, base64, os, struct, json
from dataclasses import dataclass
from typing import Generator, Tuple, Optional
from PIL import Image

try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

MAGIC = b"STG1"
SALT_LEN = 16
MAX_EXT_LEN = 20
FLAG_IS_FILE = 1 << 0
FLAG_ENCRYPTED = 1 << 1

@dataclass
class PayloadMeta:
    is_file: bool
    encrypted: bool
    ext: str
    payload_len: int

def _derive_key_from_password(password: str, salt: bytes) -> bytes:
    if not HAS_CRYPTO:
        raise RuntimeError("cryptography not installed.")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend())
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def _bytes_to_bits(data: bytes) -> Generator[int, None, None]:
    for byte in data:
        for i in range(7, -1, -1):
            yield (byte >> i) & 1

def _bits_to_bytes(bits: Generator[int, None, None], nbytes: int) -> bytes:
    out = bytearray()
    for _ in range(nbytes):
        b = 0
        for i in range(7, -1, -1):
            b |= (next(bits) & 1) << i
        out.append(b)
    return bytes(out)

def _lsb_bitstream_from_image(img: Image.Image) -> Generator[int, None, None]:
    for (r, g, b) in img.getdata():
        yield r & 1; yield g & 1; yield b & 1

def _capacity_bytes(img: Image.Image) -> int:
    return (img.width * img.height * 3) // 8

def _set_lsb(value: int, bit: int) -> int:
    return (value & ~1) | (bit & 1)

def _embed_bits_into_image(img: Image.Image, bits: Generator[int, None, None], total_bits: int) -> Image.Image:
    data = list(img.getdata()); new_data = []; bit_taken = 0
    for (r, g, b) in data:
        if bit_taken < total_bits: r = _set_lsb(r, next(bits)); bit_taken += 1
        if bit_taken < total_bits: g = _set_lsb(g, next(bits)); bit_taken += 1
        if bit_taken < total_bits: b = _set_lsb(b, next(bits)); bit_taken += 1
        new_data.append((r, g, b))
        if bit_taken >= total_bits:
            new_data.extend(data[len(new_data):]); break
    out = Image.new("RGB", img.size); out.putdata(new_data)
    return out

def _build_header(is_file: bool, encrypted: bool, ext: str, payload_len: int, salt: Optional[bytes]) -> bytes:
    flags = (FLAG_IS_FILE if is_file else 0) | (FLAG_ENCRYPTED if encrypted else 0)
    ext_bytes = ext.encode() if is_file else b""
    header = bytearray(MAGIC)
    header += bytes([flags, len(ext_bytes)])
    header += struct.pack("!I", payload_len)
    if encrypted: header += salt
    header += ext_bytes
    return bytes(header)

def _parse_header(bits) -> Tuple[PayloadMeta, Optional[bytes]]:
    fixed = _bits_to_bytes(bits, 10)
    if fixed[:4] != MAGIC: raise ValueError("Invalid stego header")
    flags, ext_len = fixed[4], fixed[5]
    payload_len = struct.unpack("!I", fixed[6:10])[0]
    encrypted, is_file = bool(flags & FLAG_ENCRYPTED), bool(flags & FLAG_IS_FILE)
    salt = _bits_to_bytes(bits, SALT_LEN) if encrypted else None
    ext = _bits_to_bytes(bits, ext_len).decode() if ext_len else ""
    return PayloadMeta(is_file, encrypted, ext, payload_len), salt

def embed(cover, output, message=None, file_path=None, password=None):
    if (message is None) == (file_path is None):
        raise ValueError("Give message OR file only")
    img = Image.open(cover).convert("RGB"); cap = _capacity_bytes(img)
    if message: raw = message.encode(); is_file, ext = False, ""
    else:
        raw = open(file_path, "rb").read(); is_file, ext = True, os.path.splitext(file_path)[1].strip(".")[:MAX_EXT_LEN]
    salt = os.urandom(SALT_LEN) if password else None; encrypted = bool(password)
    if encrypted:
        key = _derive_key_from_password(password, salt); raw = Fernet(key).encrypt(raw)
    header = _build_header(is_file, encrypted, ext, len(raw), salt)
    if len(header)+len(raw) > cap: raise ValueError("Payload too large")
    def bits(): 
        for b in header+raw:
            for i in range(7,-1,-1): yield (b>>i)&1
    out_img = _embed_bits_into_image(img, bits(), (len(header)+len(raw))*8)
    out_img.save(output, format="PNG")
    return {"cover": cover, "output": output, "capacity": cap, "embedded": len(header)+len(raw), "encrypted": encrypted}

def extract(stego, password=None):
    img = Image.open(stego).convert("RGB"); bits = _lsb_bitstream_from_image(img)
    meta, salt = _parse_header(bits)
    data = _bits_to_bytes(bits, meta.payload_len)
    if meta.encrypted:
        if not password: raise ValueError("Password needed")
        key = _derive_key_from_password(password, salt)
        data = Fernet(key).decrypt(data)
    return data, meta

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    p1=sub.add_parser("embed-text"); p1.add_argument("-i","--input"); p1.add_argument("-o","--output"); p1.add_argument("-m","--message"); p1.add_argument("--password")
    p2=sub.add_parser("embed-file"); p2.add_argument("-i","--input"); p2.add_argument("-o","--output"); p2.add_argument("-f","--file"); p2.add_argument("--password")
    p3=sub.add_parser("extract"); p3.add_argument("-i","--input"); p3.add_argument("--password"); p3.add_argument("-o","--output")
    args=p.parse_args()
    if args.cmd=="embed-text": print(json.dumps(embed(args.input,args.output,message=args.message,password=args.password),indent=2))
    elif args.cmd=="embed-file": print(json.dumps(embed(args.input,args.output,file_path=args.file,password=args.password),indent=2))
    elif args.cmd=="extract":
        data,meta=extract(args.input,password=args.password)
        if meta.is_file:
            out=args.output or "extracted."+meta.ext; open(out,"wb").write(data); print(f"[+] File saved: {out}")
        else:
            print("[+] Message:",data.decode(errors="ignore"))
if __name__=="__main__": main()
