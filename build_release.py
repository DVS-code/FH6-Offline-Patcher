import argparse
import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from engine import VERSION

ROOT = Path(__file__).resolve().parent
DEPENDENCIES = ("capstone", "pefile", "PyNaCl", "cffi", "pycparser", "pyinstaller")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_identity():
    paths = sorted(ROOT.glob("*.py")) + [ROOT / "recognition_profiles.json", ROOT / "requirements-build.txt"]
    return {p.name: digest(p) for p in paths}


def notices(destination):
    destination.mkdir()
    index = []
    for name in DEPENDENCIES:
        dist = metadata.distribution(name)
        paths = [f for f in dist.files or () if any(word in f.name.lower() for word in ("license", "copying", "notice"))]
        if not paths:
            raise RuntimeError(f"Missing installed license text: {name}")
        for i, path in enumerate(paths):
            filename = f"{name}-{i}-{path.name}"
            shutil.copyfile(dist.locate_file(path), destination / filename)
            index.append(f"{name} {dist.version}: {filename}")
    python_license = Path(sys.base_prefix) / "LICENSE.txt"
    shutil.copyfile(python_license, destination / "Python-LICENSE.txt")
    index.append(f"Python {sys.version.split()[0]}: Python-LICENSE.txt")
    for path in sorted((Path(sys.base_prefix) / "tcl").rglob("*")):
        if path.is_file() and path.name.lower() in ("license.terms", "license", "license.txt"):
            filename = "TclTk-" + "-".join(path.relative_to(Path(sys.base_prefix) / "tcl").parts)
            shutil.copyfile(path, destination / filename)
            index.append(f"Tcl/Tk: {filename}")
    (destination / "INDEX.txt").write_text("Bundled third-party software notices\n\n" + "\n".join(index) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Build the standalone Windows release executable.")
    parser.add_argument("--out-dir", type=Path, required=True, help="New folder for FH6OfflinePatcher.exe")
    parser.add_argument("--manifest", type=Path, help="Optional build manifest path outside the release folder")
    args = parser.parse_args()
    if os.name != "nt" or sys.maxsize <= 2**32:
        raise SystemExit("Build on Windows x64")
    destination = args.out_dir.absolute()
    if destination.exists() or not destination.parent.is_dir():
        raise SystemExit("Choose a new output folder under an existing parent")
    if args.manifest:
        record = args.manifest.resolve()
        if record.is_relative_to(destination.resolve()) or record.exists() or not record.parent.is_dir():
            raise SystemExit("Choose a new manifest path outside the release folder")
    expected_source = source_identity()
    versions = {name: metadata.version(name) for name in DEPENDENCIES}
    for line in (ROOT / "requirements-build.txt").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            name, version = line.split("==")
            if metadata.version(name) != version:
                raise SystemExit(f"Install the pinned build dependency: {line}")
    work = Path(tempfile.mkdtemp(prefix="fh6-offline-build-"))
    notice_directory = work / "THIRD_PARTY_NOTICES"
    notices(notice_directory)
    command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
               "--name", "FH6OfflinePatcher", "--distpath", str(work / "dist"),
               "--workpath", str(work / "work"), "--specpath", str(work),
               "--add-data", str(ROOT / "recognition_profiles.json") + os.pathsep + ".",
               "--add-data", str(notice_directory) + os.pathsep + "THIRD_PARTY_NOTICES",
               "--collect-all", "capstone", "--collect-all", "nacl",
               "--hidden-import", "_cffi_backend", str(ROOT / "patcher.py")]
    print("Building FH6 Offline Patcher " + VERSION + ".", flush=True)
    with (work / "build.log").open("w", encoding="utf-8") as log:
        result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f"Build failed; see {work / 'build.log'}")
    binary = work / "dist/FH6OfflinePatcher.exe"
    if source_identity() != expected_source:
        raise SystemExit("Source changed during compilation; rebuild before packaging")
    manifest = {"version": VERSION, "source": expected_source, "dependencies": versions,
                "python": sys.version, "binary_sha256": digest(binary),
                "release_assets": ["FH6OfflinePatcher.exe"],
                "third_party_notices_bundled": True,
                "notice_files": {p.name: digest(p) for p in notice_directory.iterdir() if p.is_file()}}
    (work / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    destination.mkdir()
    output = destination / "FH6OfflinePatcher.exe"
    shutil.copyfile(binary, output)
    if digest(output) != manifest["binary_sha256"]:
        raise SystemExit("Release executable failed disk read-back")
    if args.manifest:
        with args.manifest.open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
    print(f"Release executable: {output.resolve()}")
    print(f"Build record: {args.manifest.resolve() if args.manifest else work / 'build-manifest.json'}")


if __name__ == "__main__":
    main()
