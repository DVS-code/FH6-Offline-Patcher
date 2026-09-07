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
import zipfile

from engine import VERSION

ROOT = Path(__file__).resolve().parent
DEPENDENCIES = ("capstone", "pefile", "PyNaCl", "cffi", "pycparser", "pyinstaller")
DOCUMENTS = ("README.md", "RELEASE_NOTES.md", "VALIDATION.md", "REQUIREMENTS.md", "requirements-build.txt", ".gitignore")


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


def archive(directory, destination):
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                if path.is_symlink():
                    raise RuntimeError("Refusing symlink in release payload")
                output.write(path, path.relative_to(directory))


def main():
    parser = argparse.ArgumentParser(description='Build a Windows patcher and assemble a game-file-free GitHub release folder.')
    parser.add_argument("--out-dir", type=Path, required=True, help="New release folder")
    parser.add_argument("--binary", type=Path, help="Reuse a tested EXE with an adjacent matching build-manifest.json")
    args = parser.parse_args()
    if os.name != "nt" or sys.maxsize <= 2**32:
        raise SystemExit("Build on Windows x64")
    if args.out_dir.exists() or not args.out_dir.absolute().parent.is_dir():
        raise SystemExit("Choose a new output folder under an existing parent")
    expected_source = source_identity()
    versions = {name: metadata.version(name) for name in DEPENDENCIES}
    for line in (ROOT / "requirements-build.txt").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            name, version = line.split("==")
            if metadata.version(name) != version:
                raise SystemExit(f"Install the pinned build dependency: {line}")
    if args.binary:
        binary = args.binary.resolve()
        manifest = json.loads(binary.with_name("build-manifest.json").read_text())
        if manifest["source"] != expected_source or manifest["binary_sha256"] != digest(binary):
            raise SystemExit("Tested binary does not match the current source and recognition bundle")
    else:
        work = Path(tempfile.mkdtemp(prefix="fh6-offline-build-"))
        command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
                   "--name", "FH6OfflinePatcher", "--distpath", str(work / "dist"),
                   "--workpath", str(work / "work"), "--specpath", str(work),
                   "--add-data", str(ROOT / "recognition_profiles.json") + os.pathsep + ".",
                   "--collect-all", "capstone", "--collect-all", "nacl",
                   "--hidden-import", "_cffi_backend", str(ROOT / "patcher.py")]
        print("Building the standalone Windows executable.", flush=True)
        with (work / "build.log").open("w", encoding="utf-8") as log:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode:
            raise SystemExit(f"Build failed; see {work / 'build.log'}")
        binary = work / "dist/FH6OfflinePatcher.exe"
        if source_identity() != expected_source:
            raise SystemExit("Source changed during compilation; rebuild before packaging")
        manifest = {"version": VERSION, "source": expected_source, "dependencies": versions,
                    "python": sys.version, "binary_sha256": digest(binary)}
    args.out_dir.mkdir()
    windows, source = args.out_dir / "windows-x64", args.out_dir / "source"
    windows.mkdir()
    source.mkdir()
    shutil.copyfile(binary, windows / "FH6OfflinePatcher.exe")
    (windows / "build-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    for name in DOCUMENTS:
        shutil.copyfile(ROOT / name, source / name)
        if name.endswith(".md") and name != "REQUIREMENTS.md":
            shutil.copyfile(ROOT / name, args.out_dir / name)
            shutil.copyfile(ROOT / name, windows / name)
    for path in sorted(ROOT.glob("*.py")):
        shutil.copyfile(path, source / path.name)
    shutil.copyfile(ROOT / "recognition_profiles.json", source / "recognition_profiles.json")
    (source / "tests").mkdir()
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        shutil.copyfile(path, source / "tests" / path.name)
    notices(windows / "THIRD_PARTY_NOTICES")
    archive(windows, args.out_dir / f"FH6OfflinePatcher-{VERSION}-windows-x64.zip")
    archive(source, args.out_dir / f"FH6OfflinePatcher-{VERSION}-source.zip")
    paths = sorted(p for p in args.out_dir.rglob("*") if p.is_file())
    (args.out_dir / "SHA256SUMS.txt").write_text("".join(
        f"{digest(path)}  {path.relative_to(args.out_dir).as_posix()}\n" for path in paths), encoding="utf-8")
    print(f"Release folder prepared: {args.out_dir.resolve()}")
    print(f"Patcher SHA256: {manifest['binary_sha256']}")


if __name__ == "__main__":
    main()
