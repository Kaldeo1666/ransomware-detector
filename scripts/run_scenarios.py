"""Run attack and harmless scenarios through the REAL monitor + engine and print a tuning table.

Everything happens inside sandbox/_scenarios/, which this script creates and deletes itself.
    python scripts/run_scenarios.py                  # use config/default.yaml as it is now
    python scripts/run_scenarios.py --profile day6   # pretend the Day 7 settings do not exist
    python scripts/run_scenarios.py --only photo_rename --only inplace_fast
    python scripts/run_scenarios.py --check          # exit code 1 if anything unexpected happens
"""
import argparse
import dataclasses
import os
import queue
import random
import shutil
import sys
import time
import zipfile
from pathlib import Path

from rwdetect.config import load_config
from rwdetect.monitor import Monitor
from rwdetect.pipeline import Worker, build_engine

_real_rename, _real_unlink, _real_replace = Path.rename, Path.unlink, os.replace


def _retry(fn):
    def wrapper(*args, **kwargs):
        for attempt in range(40):
            try:
                return fn(*args, **kwargs)
            except PermissionError:
                if attempt == 39:
                    raise
                time.sleep(0.025)
    return wrapper


Path.rename, Path.unlink, os.replace = _retry(_real_rename), _retry(_real_unlink), _retry(_real_replace)

SANDBOX = Path("sandbox").resolve()
SCN_ROOT = SANDBOX / "_scenarios"
WORDS = ("invoice report budget meeting project alpha beta quarterly "
         "customer revenue forecast notes draft final review").split()
SKEW = [12 if i < 48 else 1 for i in range(256)]    # about 6.9 bits/byte, like compiled output


def text(n: int = 3000) -> bytes:
    out, size = [], 0
    while size < n:
        w = random.choice(WORDS)
        out.append(w)
        size += len(w) + 1
    return " ".join(out).encode()


def rand(n: int = 3000) -> bytes:
    return os.urandom(n)


def skewed(n: int = 3000) -> bytes:
    return bytes(random.choices(range(256), weights=SKEW, k=n))


class Recorder:
    """Lets an attack note the moment it finishes each file."""

    def __init__(self):
        self.times: list[float] = []

    def mark(self) -> None:
        self.times.append(time.time())


class Collector:
    def __init__(self):
        self.alerts: list[tuple[float, dict]] = []
        self.events = 0

    def emit(self, record: dict) -> None:
        if record["event_type"] == "alert":
            self.alerts.append((time.time(), record))
        else:
            self.events += 1

    def close(self) -> None:
        pass


# ----------------------------------------------------------------- attacks
def setup_text_files(work: Path, n: int = 40) -> None:
    for i in range(n):
        (work / f"doc_{i}.txt").write_bytes(text(random.randint(2000, 8000)))


def inplace(work: Path, rec: Recorder, delay: float = 0.0, n: int = 40) -> None:
    for i in range(n):
        f = work / f"doc_{i}.txt"
        f.write_bytes(rand(f.stat().st_size + 28))
        f.rename(f.with_name(f.name + ".locked"))
        rec.mark()
        time.sleep(delay)


def copy_delete(work: Path, rec: Recorder) -> None:
    for i in range(40):
        f = work / f"doc_{i}.txt"
        (work / f"doc_{i}.txt.locked").write_bytes(rand(f.stat().st_size + 28))
        f.unlink()
        rec.mark()


def setup_docs(work: Path) -> None:
    (work / "docs").mkdir()
    for i in range(30):
        (work / "docs" / f"doc_{i}.txt").write_bytes(text(4000))


def new_dirs(work: Path, rec: Recorder) -> None:
    """Encrypted copies are written into folders that did not exist when monitoring began."""
    for d in range(6):
        vault = work / f"vault_{d}"
        vault.mkdir()
        for j in range(5):
            i = d * 5 + j
            src = work / "docs" / f"doc_{i}.txt"
            (vault / f"doc_{i}.txt.locked").write_bytes(rand(4028))
            src.unlink()
            rec.mark()


def setup_zips(work: Path) -> None:
    for i in range(40):
        (work / f"archive_{i}.zip").write_bytes(rand(3000))     # already high entropy


def zip_locked(work: Path, rec: Recorder) -> None:
    """Compressed files encrypted in place AND renamed to .locked."""
    for i in range(40):
        f = work / f"archive_{i}.zip"
        f.write_bytes(rand(3000))
        f.rename(f.with_name(f.name + ".locked"))
        rec.mark()


def zip_inplace(work: Path, rec: Recorder) -> None:
    """Encrypts already-compressed files in place and keeps the name: a known blind spot."""
    for i in range(40):
        (work / f"archive_{i}.zip").write_bytes(rand(3000))
        rec.mark()


# ----------------------------------------------------------------- harmless
def bulk_copy(work: Path, rec: Recorder) -> None:
    src = SCN_ROOT / "_bulk_copy_src"
    shutil.rmtree(src, ignore_errors=True)
    src.mkdir(parents=True)
    for i in range(100):
        (src / f"note_{i}.txt").write_bytes(text())
    shutil.copytree(src, work / "copied")
    shutil.rmtree(src, ignore_errors=True)


def unzip_200(work: Path, rec: Recorder) -> None:
    archive = SCN_ROOT / "_extract_me.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for i in range(200):
            z.writestr(f"project/file_{i}.txt", text(1500))
    with zipfile.ZipFile(archive) as z:
        z.extractall(work)
    archive.unlink()


def setup_repo(work: Path) -> None:
    (work / "repo" / "src").mkdir(parents=True)
    (work / "repo" / ".git" / "objects").mkdir(parents=True)
    for i in range(100):
        (work / "repo" / "src" / f"module_{i}.txt").write_bytes(text(2500))


def git_checkout(work: Path, rec: Recorder) -> None:
    src = work / "repo" / "src"
    for i in range(100):
        (src / f"module_{i}.txt").write_bytes(text(2500))        # content changes
    for i in range(10):
        (src / f"module_{i}.txt").unlink()
    for i in range(100, 110):
        (src / f"module_{i}.txt").write_bytes(text(2500))
    for i in range(40):                                           # git objects are compressed
        obj = work / "repo" / ".git" / "objects" / f"{i:02x}"
        obj.mkdir(exist_ok=True)
        (obj / f"{random.getrandbits(64):016x}").write_bytes(rand(random.randint(400, 2000)))


def photo_rename(work: Path, rec: Recorder) -> None:
    box = work / "photos"
    box.mkdir()
    for i in range(50):
        (box / f"photo_{i}.jpg").write_bytes(rand())
    time.sleep(1.5)
    for i in range(50):
        (box / f"photo_{i}.jpg").rename(box / f"holiday_{i}.jpg")


def setup_docs_for_saving(work: Path) -> None:
    (work / "notes.txt").write_bytes(text())
    (work / "report.docx").write_bytes(rand(5000))


def save_spam(work: Path, rec: Recorder) -> None:
    for i in range(80):
        (work / "notes.txt").write_bytes(text())
        time.sleep(0.03)
    for i in range(30):                                           # atomic save: temp then rename
        tmp = work / "~$report.tmp"
        tmp.write_bytes(rand(5000))
        os.replace(tmp, work / "report.docx")
        time.sleep(0.03)


def setup_sources(work: Path) -> None:
    for i in range(80):
        (work / f"unit_{i}.c").write_bytes(text())


def build_outputs(work: Path, rec: Recorder) -> None:
    out = work / "build"
    out.mkdir()
    for i in range(80):
        (out / f"unit_{i}.o").write_bytes(skewed())
    time.sleep(1.0)
    for f in list(out.iterdir()):
        f.unlink()


def media_import(work: Path, rec: Recorder) -> None:
    box = work / "import"
    box.mkdir()
    for i in range(60):
        (box / f"IMG_{i}.jpg").write_bytes(rand(4000))
    for i in range(10):
        (box / f"VID_{i}.mp4").write_bytes(rand(9000))


def setup_txt(work: Path) -> None:
    for i in range(40):
        (work / f"draft_{i}.txt").write_bytes(text())


def rename_to_md(work: Path, rec: Recorder) -> None:
    for i in range(40):
        (work / f"draft_{i}.txt").rename(work / f"draft_{i}.md")


def setup_for_zip(work: Path) -> None:
    for i in range(60):
        (work / f"report_{i}.txt").write_bytes(text())


def make_backup(work: Path, rec: Recorder) -> None:
    with zipfile.ZipFile(work / "backup.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for f in sorted(work.glob("report_*.txt")):
            z.write(f, f.name)


def cache_dat(work: Path, rec: Recorder) -> None:
    box = work / "appcache"
    box.mkdir()
    for i in range(40):
        (box / f"cache_{i}.dat").write_bytes(rand())


def nothing(work: Path) -> None:
    pass


# name, kind, setup, action, note
SCENARIOS = [
    ("inplace_fast", "attack", setup_text_files, inplace, "encrypt 40 files in place, rename to .locked"),
    ("copy_delete", "attack", setup_text_files, copy_delete, "write 40 .locked copies, delete originals"),
    ("inplace_slow", "attack", setup_text_files,
     lambda w, r: inplace(w, r, delay=1.0, n=12), "12 files, one per second"),
    ("new_dirs", "attack", setup_docs, new_dirs, "copies written into folders created mid-attack"),
    ("zip_locked", "attack", setup_zips, zip_locked, "compressed files encrypted and renamed to .locked"),
    ("zip_same_name", "attack_blind", setup_zips, zip_inplace, "compressed files encrypted, name kept"),
    ("bulk_copy", "benign", nothing, bulk_copy, "copy 100 text files"),
    ("unzip_200", "benign", nothing, unzip_200, "extract an archive of 200 files"),
    ("git_checkout", "benign", setup_repo, git_checkout, "rewrite 100 files + 40 compressed .git objects"),
    ("photo_rename", "benign", nothing, photo_rename, "create 50 jpgs, rename all 50"),
    ("save_spam", "benign", setup_docs_for_saving, save_spam, "80 saves + 30 atomic temp-rename saves"),
    ("build_outputs", "benign", setup_sources, build_outputs, "80 .o files appear, then vanish"),
    ("media_import", "benign", nothing, media_import, "import 60 jpgs + 10 mp4s"),
    ("rename_to_md", "benign", setup_txt, rename_to_md, "rename 40 .txt files to .md"),
    ("zip_backup", "benign", setup_for_zip, make_backup, "compress 60 files into one zip"),
    ("cache_dat", "known_fp", nothing, cache_dat, "app writes 40 random .dat cache files"),
]


def run_scenario(name, kind, setup, action, config) -> dict:
    work = SCN_ROOT / name
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    random.seed(7)
    setup(work)

    cfg = dataclasses.replace(config, watch_dir=work)
    engine = build_engine(cfg)
    collector = Collector()
    q = queue.Queue(maxsize=cfg.queue_size)
    worker = Worker(q, [collector], engine)
    monitor = Monitor(cfg, q)
    worker.start()
    monitor.start()
    time.sleep(0.6)                                  # let the OS watcher settle

    rec = Recorder()
    started = time.time()
    action(work, rec)
    time.sleep(1.5)                                  # let the pipeline catch up
    monitor.stop()
    worker.stop()

    first = collector.alerts[0] if collector.alerts else None
    levels = ["info", "medium", "high", "critical"]
    worst = max((levels.index(a["severity"]) for _, a in collector.alerts), default=0)
    hit_before = sum(1 for t in rec.times if first and t <= first[0]) if first else None
    result = {
        "name": name, "kind": kind, "peak": engine.peak_score, "alerts": len(collector.alerts),
        "worst": levels[worst] if collector.alerts else "-",
        "ttd": round(first[0] - started, 2) if first else None,
        "files_hit": hit_before, "events": collector.events,
    }
    shutil.rmtree(work, ignore_errors=True)
    return result


def verdict(r: dict) -> tuple[str, bool]:
    alerted = r["alerts"] > 0
    if r["kind"] == "attack":
        return ("DETECTED", True) if alerted else ("MISSED", False)
    if r["kind"] == "attack_blind":
        return ("MISSED (known blind spot)", True) if not alerted else ("detected (surprise!)", True)
    if r["kind"] == "known_fp":
        return ("ALERT (known limitation)", True) if alerted else ("quiet", True)
    return ("ok", True) if not alerted else ("FALSE ALARM", False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--config", default="config/default.yaml")
    parser.add_argument("--profile", choices=["current", "day6"], default="current")
    parser.add_argument("--only", action="append", default=[])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if not (SANDBOX / ".RWDETECT_SANDBOX").is_file():
        sys.exit("REFUSED: sandbox/.RWDETECT_SANDBOX marker not found")
    config = load_config(args.config)
    if args.profile == "day6":
        config.detection["gate_signals"] = []
        config.ignore_dirs = []

    SCN_ROOT.mkdir(exist_ok=True)
    print(f"profile={args.profile}  gate={config.detection['gate_signals']}  "
          f"ignore_dirs={config.ignore_dirs}\n")
    header = f"{'scenario':14} {'kind':12} {'peak':>4} {'alerts':>6} {'worst':>8} {'ttd(s)':>7} {'hit':>4}  verdict"
    print(header)
    print("-" * len(header))

    problems = 0
    for name, kind, setup, action, _note in SCENARIOS:
        if args.only and name not in args.only:
            continue
        r = run_scenario(name, kind, setup, action, config)
        text_verdict, ok = verdict(r)
        problems += 0 if ok else 1
        ttd = "-" if r["ttd"] is None else f"{r['ttd']:.2f}"
        hit = "-" if r["files_hit"] is None else str(r["files_hit"])
        print(f"{name:14} {kind:12} {r['peak']:>4} {r['alerts']:>6} {r['worst']:>8} {ttd:>7} {hit:>4}  {text_verdict}",
              flush=True)

    shutil.rmtree(SCN_ROOT, ignore_errors=True)
    print(f"\n{problems} unexpected result(s)")
    if args.check and problems:
        sys.exit(1)


if __name__ == "__main__":
    main()