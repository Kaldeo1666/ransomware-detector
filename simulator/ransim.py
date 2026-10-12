"""SAFE ransomware behaviour simulator. Sandbox-only, reversible, test files only."""
import argparse
import hashlib
import json
import os
import random
import sys
import time
import zipfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MARKER = ".RWDETECT_SANDBOX"
STATE_DIR = Path(__file__).resolve().parent / ".state"
MANIFEST_PATH = STATE_DIR / "manifest.json"
KEY_PATH = STATE_DIR / "key.bin"
MAX_FILES = 500
LOCKED_EXT = ".locked"
NONCE_LEN = 12
WORDS = ("invoice report budget meeting project alpha beta quarterly "
         "customer revenue forecast notes draft final review").split()


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check_sandbox(target: str) -> Path:
    root = Path(target).resolve()
    if not root.is_dir():
        sys.exit(f"REFUSED: {root} is not a folder")
    if root == Path(root.anchor):
        sys.exit("REFUSED: will not run on a drive root")
    if not (root / MARKER).is_file():
        sys.exit(f"REFUSED: {root} has no {MARKER} marker file")
    return root


def is_safe_file(root: Path, path: Path) -> bool:
    return (
        path.is_file()
        and not path.is_symlink()
        and path.resolve().is_relative_to(root)
    )


def load_manifest(root: Path) -> dict:
    if not MANIFEST_PATH.is_file():
        sys.exit("No manifest found. Run 'generate' first.")
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    if manifest["root"] != str(root):
        sys.exit("REFUSED: manifest belongs to a different folder")
    return manifest


def make_text(size: int) -> bytes:
    words, total = [], 0
    while total < size:
        w = random.choice(WORDS)
        words.append(w)
        total += len(w) + 1
    return " ".join(words).encode()


def targets(root: Path, manifest: dict):
    for rel in manifest["files"]:
        path = root / rel
        if path.resolve().is_relative_to(root):
            yield rel, path


def load_key() -> bytes:
    if KEY_PATH.is_file():
        return KEY_PATH.read_bytes()
    STATE_DIR.mkdir(exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    KEY_PATH.write_bytes(key)
    return key


def cmd_generate(args) -> None:
    root = check_sandbox(args.dir)
    if args.count > MAX_FILES:
        sys.exit(f"REFUSED: max {MAX_FILES} files")
    if MANIFEST_PATH.exists():
        sys.exit("Files already generated. Run 'clean' first.")

    folders = [root, root / "docs", root / "docs" / "2026", root / "photos"]
    for folder in folders:
        folder.mkdir(exist_ok=True)

    manifest = {"root": str(root), "files": {}}
    for i in range(args.count):
        folder = folders[i % len(folders)]
        if i % 5 == 4:
            path = folder / f"archive_{i}.zip"
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                z.writestr("data.txt", make_text(8000))
        else:
            ext = (".txt", ".csv", ".md")[i % 3]
            path = folder / f"file_{i}{ext}"
            path.write_bytes(make_text(random.randint(2000, 20000)))
        manifest["files"][str(path.relative_to(root))] = sha256_of(path)

    STATE_DIR.mkdir(exist_ok=True)
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Generated {args.count} files in {root}")


def cmd_clean(args) -> None:
    root = check_sandbox(args.dir)
    manifest = load_manifest(root)
    removed = 0
    for rel in manifest["files"]:
        for path in (root / rel, root / (rel + LOCKED_EXT)):
            if is_safe_file(root, path):
                path.unlink()
                removed += 1
    MANIFEST_PATH.unlink()
    KEY_PATH.unlink(missing_ok=True)
    print(f"Removed {removed} files")


def cmd_attack(args) -> None:
    root = check_sandbox(args.dir)
    manifest = load_manifest(root)
    aes = AESGCM(load_key())
    done = 0
    for rel, path in targets(root, manifest):
        if args.files and done >= args.files:
            break
        if not is_safe_file(root, path):
            continue
        locked = path.with_name(path.name + LOCKED_EXT)
        print(f"{'WOULD ENCRYPT' if args.dry_run else 'ENCRYPT'} {rel}")
        if not args.dry_run:
            nonce = os.urandom(NONCE_LEN)
            blob = nonce + aes.encrypt(nonce, path.read_bytes(), None)
            if args.style == "inplace":
                path.write_bytes(blob)
                path.replace(locked)
            else:
                locked.write_bytes(blob)
                path.unlink()
        done += 1
        time.sleep(args.delay)
    verb = "Would encrypt" if args.dry_run else "Encrypted"
    print(f"{verb} {done} files")


def cmd_restore(args) -> None:
    root = check_sandbox(args.dir)
    manifest = load_manifest(root)
    if not KEY_PATH.is_file():
        sys.exit("No key found; nothing to restore.")
    aes = AESGCM(KEY_PATH.read_bytes())
    restored = problems = 0
    for rel, path in targets(root, manifest):
        locked = path.with_name(path.name + LOCKED_EXT)
        if not is_safe_file(root, locked):
            continue
        blob = locked.read_bytes()
        try:
            plain = aes.decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], None)
        except InvalidTag:
            print(f"FAILED (corrupt or wrong key): {rel}")
            problems += 1
            continue
        path.write_bytes(plain)
        locked.unlink()
        ok = sha256_of(path) == manifest["files"][rel]
        problems += 0 if ok else 1
        restored += 1
        print(f"{'OK      ' if ok else 'MISMATCH'} {rel}")
    print(f"Restored {restored} files, {problems} problems")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    gen = sub.add_parser("generate", help="create dummy files")
    gen.add_argument("--dir", default="sandbox")
    gen.add_argument("--count", type=int, default=40)
    gen.set_defaults(func=cmd_generate)

    clean = sub.add_parser("clean", help="remove files this tool generated")
    clean.add_argument("--dir", default="sandbox")
    clean.set_defaults(func=cmd_clean)

    atk = sub.add_parser("attack", help="encrypt generated files (reversible)")
    atk.add_argument("--dir", default="sandbox")
    atk.add_argument("--style", choices=["inplace", "copy-delete"], default="inplace")
    atk.add_argument("--files", type=int, default=0, help="limit file count (0 = all)")
    atk.add_argument("--delay", type=float, default=0.0, help="seconds between files")
    atk.add_argument("--dry-run", action="store_true")
    atk.set_defaults(func=cmd_attack)

    res = sub.add_parser("restore", help="decrypt files back")
    res.add_argument("--dir", default="sandbox")
    res.set_defaults(func=cmd_restore)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()