from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from reconstruction import reconstruct
from static_container import ContainerError, find_footers, instructions, open_container, transforms
from static_image import Image, discover_xor_codec


def discover_container(image: Image, directory: Path, exe: Path):

    candidates = []
    for path in sorted(directory.iterdir()):
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or path.is_symlink()
                or getattr(metadata, "st_file_attributes", 0) & 0x400
                or path.resolve() == exe.resolve()):
            continue
        with path.open("rb") as stream:
            stream.seek(max(0, metadata.st_size - 8232))
            base_offset = stream.tell()
            if not find_footers(stream.read(), base_offset=base_offset):
                continue
            stream.seek(0)
            data = stream.read()
        try:
            container = open_container(data)
            if len(container.table(2)) != 8:
                continue
            native = instructions(container)
            startup = transforms(container, 3)
            dynamic = transforms(container, 1)
            if not native or not startup or not dynamic:
                continue
            for record in native:
                image.offset(record.rva, len(record.data), executable=True)
            for record in startup:
                rva, size = record.targets[0]
                image.offset(rva, size, executable=True)
            for record in dynamic:
                start, prefix = record.targets[0]
                image.offset(start, prefix + record.size, executable=True)
        except ContainerError:
            continue
        candidates.append((path, data, container))
    if len(candidates) != 1:
        raise ContainerError(f"Expected one compatible original support container; found {len(candidates)}")
    return candidates[0]


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='Inspect/reconstruct original game files offline; never publish a game EXE.')
    parser.add_argument("exe", type=Path)
    parser.add_argument("--game-dir", type=Path, help="Search this directory for the original support container")
    parser.add_argument("--out-dir", type=Path, required=True, help="New directory for analysis artifacts")
    args = parser.parse_args(argv)
    try:
        if args.out_dir.exists():
            raise ContainerError("Refusing to overwrite an existing analysis directory")
        image = Image(args.exe.read_bytes())
        path, container_bytes, container = discover_container(
            image, args.game_dir or args.exe.parent, args.exe
        )
        print("Authenticated support container discovered; analyzing the EXE's XOR loop.", flush=True)
        codec = discover_xor_codec(image)
        print("Reconstructing code from original files; no game process is used.", flush=True)
        output, report = reconstruct(image, container, codec)
        report.update({
            "input_exe": str(args.exe.resolve()),
            "input_container": str(path.resolve()),
            "input_container_sha256": hashlib.sha256(container_bytes).hexdigest(),
            "github_release_ready": False,
        })

        if args.exe.read_bytes() != image.data or path.read_bytes() != container_bytes:
            raise ContainerError("An original input changed during analysis")
        args.out_dir.mkdir(parents=True, exist_ok=False)
        for name, data in (("reconstructed.analysis.bin", output),
                           ("analysis.json", (json.dumps(report, indent=2) + "\n").encode())):
            with (args.out_dir / name).open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        print(json.dumps({"analysis_directory": str(args.out_dir.resolve()),
                          "native_instructions": report["native_instruction_records"],
                          "dynamic_records": report["dynamic_records"],
                          "startup_records": report["startup_records"],
                          "bootable_patched_game": False}, indent=2))
        return 0
    except (ContainerError, OSError) as error:
        print(f"Analysis refused: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
