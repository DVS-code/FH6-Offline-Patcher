from contextlib import ExitStack, contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile

from allocation import discover_allocation_site
from allocation_helpers import emit_allocation_helpers
from embedded_container import add_readonly_section, without_code_transforms, checksum_valid
from inspect_static_inputs import discover_container
from patch_actions import apply_plan
from planning import discover_reviewed_plan
from recognition import Profile
from reconstruction import reconstruct
from static_container import ContainerError, open_container
from static_image import Image, discover_xor_codec
from static_semantics import discover_embedded_container_name, exception_records

VERSION = "V1"


@contextmanager
def locked_original(path):

    if os.name == "nt":
        import ctypes as c
        from ctypes import wintypes as w
        import msvcrt
        kernel = c.WinDLL("kernel32", use_last_error=True)
        kernel.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p,
                                      w.DWORD, w.DWORD, w.HANDLE]
        kernel.CreateFileW.restype = w.HANDLE
        kernel.CloseHandle.argtypes = [w.HANDLE]
        handle = kernel.CreateFileW(str(path.resolve()), 0x80000000, 1, None, 3, 0x80, None)
        if handle == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        try:
            descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        except BaseException:
            kernel.CloseHandle(handle)
            raise
        with os.fdopen(descriptor, "rb") as stream:
            yield stream.read()
    else:
        with path.open("rb") as stream:
            yield stream.read()


def bundled_profiles():
    path = Path(__file__).with_name("recognition_profiles.json")
    data = path.read_bytes()
    document = json.loads(data)
    if document.get("schema") != 3:
        raise ContainerError("Recognition bundle lacks required dependency validation")
    profiles = [Profile.from_json(row) for row in document["profiles"]]
    for profile in profiles:
        if profile.validation is None or (profile.validation.get("kind") != "argument_only_leaf"
                and "dependencies" not in profile.validation):
            raise ContainerError("Incomplete recognition dependency bundle")
    return profiles, hashlib.sha256(data).hexdigest()


def publish_directory(destination, files):

    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ContainerError("Output directory already exists; choose a new directory")
    if not destination.parent.is_dir():
        raise ContainerError("Output parent directory does not exist")
    staging = Path(tempfile.mkdtemp(prefix=".fh6-patch-", dir=destination.parent)).resolve()
    committed = False
    try:
        for name, data in files.items():
            if Path(name).name != name or name in (".", ".."):
                raise ContainerError("Invalid output filename")
            with (staging / name).open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if hashlib.sha256((staging / name).read_bytes()).digest() != hashlib.sha256(data).digest():
                raise ContainerError("Output file failed disk read-back")


        if destination.exists() or destination.is_symlink():
            raise ContainerError("Output appeared during preparation; refusing overwrite")
        staging.rename(destination)
        committed = True
    finally:
        if not committed:

            for name in files:
                if Path(name).name == name and (staging / name).is_file():
                    (staging / name).unlink()
            staging.rmdir()


def patch(exe, game_dir, out_dir, progress=print):
    exe, game_dir, out_dir = Path(exe), Path(game_dir), Path(out_dir)
    if out_dir.exists() or out_dir.is_symlink():
        raise ContainerError("Output directory already exists; choose a new directory")
    if not out_dir.absolute().parent.is_dir():
        raise ContainerError("Output parent directory does not exist")
    profiles, profile_hash = bundled_profiles()
    with ExitStack() as stack:
        progress("Reading the selected original EXE.")
        original_bytes = stack.enter_context(locked_original(exe))
        original = Image(original_bytes)
        progress("Discovering the matching original support file by authenticated content.")
        support_path, discovered_bytes, container = discover_container(original, game_dir, exe)
        support_bytes = stack.enter_context(locked_original(support_path))
        if support_bytes != discovered_bytes:
            raise ContainerError("Original support file changed during discovery")
        codec = discover_xor_codec(original)
        progress("Reconstructing protected code and checking independent EXE metadata.")
        native, reconstruction = reconstruct(original, container, codec)
        image = Image(native)
        name, name_evidence = discover_embedded_container_name(image, codec)
        progress("Discovering patch roles and validating control flow and dependencies.")
        actions = discover_reviewed_plan(image, profiles, require_region_validation=True)
        site = discover_allocation_site(image)
        progress("Constructing static allocation helpers and native unwind metadata.")
        extended, allocation_actions, helpers = emit_allocation_helpers(image, site)
        actions.extend(allocation_actions)
        patched = apply_plan(Image(extended), actions)
        sealed = without_code_transforms(support_bytes)
        result, section = add_readonly_section(patched, name, sealed)
        progress("Validating the final EXE, loader metadata, and every patch.")
        final = Image(result)
        embedded = open_container(final.read(int(section["rva"], 16), section["virtual_size"]))
        if embedded.table(1) or embedded.table(3) or embedded.table(0) != container.table(0):
            raise ContainerError("Embedded loader metadata failed read-back")
        if not checksum_valid(final):
            raise ContainerError("Final PE checksum failed")
        exception_records(final)
        for action in actions:
            if final.read(action.rva, len(action.after)) != action.after:
                raise ContainerError(f"Final patch verification failed: {action.role}")
        if exe.read_bytes() != original_bytes or support_path.read_bytes() != support_bytes:
            raise ContainerError("An original input changed during preparation")
        report = {
            "patcher_version": VERSION, "offline": True, "runtime_patch_dll_required": False,
            "input_exe_name": exe.name, "support_file_name": support_path.name,
            "input_exe_sha256": hashlib.sha256(original_bytes).hexdigest(),
            "input_support_sha256": hashlib.sha256(support_bytes).hexdigest(),
            "recognition_bundle_sha256": profile_hash,
            "output_sha256": hashlib.sha256(result).hexdigest(), "output_size": len(result),
            "action_count": len(actions), "reconstruction": reconstruction,
            "loader_section_name": name_evidence, "embedded_container_section": section,
            "allocation": site.evidence(), "helpers": helpers,
            "patches": [{"role": p.role, "rva": hex(p.rva), "before": p.before.hex(),
                         "after": p.after.hex(), "evidence": p.evidence} for p in actions],
            "limits": ["Recognition requires supported compiler and container shapes.",
                       "Structural validation does not guarantee every future game build.",
                       "This output has passed offline validation; this job does not launch-test it."]}
        progress("Writing the verified EXE and report into a new output folder.")
        publish_directory(out_dir, {
            "forzahorizon6.exe": result,
            "patch-report.json": (json.dumps(report, indent=2) + "\n").encode(),
            "READ_ME.txt": ("Offline patched FH6 EXE. Original inputs were not modified.\r\n"
                            "Use with the matching complete game installation and original game dependencies.\r\n"
                            "Keep your original EXE to restore it. No patch DLL is required.\r\n"
                            "See patch-report.json for validation and compatibility limits.\r\n").encode()})
        return report
