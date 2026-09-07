# FH6 Offline Patcher

Create a modified Forza Horizon 6 EXE from your own original game files, entirely
offline. The patcher discovers locations in the selected EXE, reconstructs its
protected code from the matching original support file, and applies the reviewed
debugging/protection fixes. The resulting EXE requires no patch DLL.

[Download the Windows release](https://github.com/DVS-code/FH6-Offline-Patcher/releases/tag/v0.1.0-rc3)
| [Public source](https://github.com/DVS-code/FH6-Offline-Patcher)

**Release candidate: 0.1.0-rc3.** Builds 430.771 and 440.853 have passed original-file
construction, save loading, driving, later debugger attachment, breakpoints,
pause/resume, and normal exit. The 440.853 gameplay result was confirmed by the
user during the monitored test. See [VALIDATION.md](VALIDATION.md).

## Windows requirements

- Windows 10 or 11, **64-bit Intel/AMD (x64)**. 32-bit Windows is unsupported;
  older Windows and Windows on ARM have not been qualified.
- Everything the patcher needs is bundled: Python, the GUI toolkit, native
  disassembler, cryptography libraries, and required Visual C++ runtime.
  No Python installation, compiler, debugger, internet connection, or admin
  privileges are needed for ordinary readable inputs and writable output.
- Your clean FH6 EXE and matching original support file; a writable temporary
  folder and a new output folder. Allow working space for the generated EXE.
  Running the game still requires its complete installation and dependencies.

The package has been checked independently of developer PATH/Python settings.
This is a portable Windows x64 application, not a guarantee for every Windows
version, architecture, security policy, or hardware configuration.

## Use

1. Extract the Windows package and open `FH6OfflinePatcher.exe`.
2. Select a clean, original FH6 EXE.
3. Select the matching original game folder if it differs from the EXE folder.
   The support file is discovered by authenticated content, without a fixed name.
4. Choose a **new** output folder and click **Create patched EXE**.

The output contains `forzahorizon6.exe`, `patch-report.json`, and `READ_ME.txt`.
Original inputs and existing outputs are never overwritten. Use the result with
the matching complete game installation. Keep the original EXE to restore it.
The patcher does not copy the rest of the game or install the result for you.

Command-line usage:

```powershell
.\FH6OfflinePatcher.exe "C:\Game\forzahorizon6.exe" --out-dir "C:\FH6-patched"
.\FH6OfflinePatcher.exe "C:\Clean\forzahorizon6.exe" --game-dir "C:\Game" --out-dir "C:\FH6-patched"
```

Allow several minutes for validation. The game need not be running. The patcher
does not access an account, the network, another process, or the installed game
for writing. The game itself retains its normal account and installation needs.

## Compatibility

Patch locations, branch destinations, object fields, imports, allocation cleanup,
codec parameters, and loader metadata are discovered from the inputs. There is
no fixed game-RVA table, executable-hash whitelist, replacement EXE, binary delta,
captured plaintext, or runtime patch DLL in the package.

Version rc2 corrects normalization of SIMD RIP displacements and derives static
TLS field operands from the selected EXE's TLS metadata and code. Verified TLS
access widths, initial values, and repeated-field relationships are retained.

Recognition uses reviewed instruction patterns and address-normalized function
and dependency fingerprints. These are checks, not replacement code. They still
describe supported compiler shapes; this is not a mechanism that can understand
arbitrary future protection code. Missing, changed, or ambiguous discoveries
stop the job before an output directory is published. A refusal does not mean a
build is supported. Newer-build compatibility must be established with matching
original files and gameplay tests from those builds.

The container parser supports the observed serialized format. EXE/support
association is checked using independent PE instruction boundaries and the full
patch validation plan; it is not a cryptographic binding between the two files.
Direct native references and imports are checked. Writable globals are classified
by their layout and use; arbitrary transitive program equivalence is not proved.

## Build and test

Windows x64, Python 3.11:

```powershell
python -m pip install -r requirements-build.txt
python -m unittest discover -s tests -v
python patcher.py --help
python build_release.py --out-dir "C:\Builds\FH6OfflinePatcher-0.1.0-rc3"
```

The build creates a portable executable, source archive, third-party notices,
release notes, and SHA-256 checksums. No game files or private test artifacts are
included. The standalone `inspect_static_inputs.py` tool writes an analysis image
only; use `patcher.py` to create a game EXE.
