# FH6 Offline Patcher V2

Create a patched Forza Horizon 6 EXE from your original game files offline.

The release download is `FH6OfflinePatcher.exe`. Source code is on `main`.

## Requirements

- Windows 10 or 11, 64-bit (x64).
- Your original FH6 EXE and matching game support files.
- Space for a new output folder. All patcher dependencies are included.

## Use

1. Open `FH6OfflinePatcher.exe`.
2. Select your original FH6 EXE. Select the game folder if the support files are elsewhere.
3. Choose a new output folder and click **Create patched EXE**.
4. Close the game, back up its installed EXE, then copy the generated `forzahorizon6.exe` into the game folder.

The patcher writes the result to your chosen output folder and leaves the original files intact.

## Command line

```powershell
.\FH6OfflinePatcher.exe "C:\Game\forzahorizon6.exe" --out-dir "C:\FH6-patched"
```

Add `--game-dir "C:\Game"` if the support files are in a different folder.

## Build from source

Use Python 3.11 on Windows x64. From the source folder:

```powershell
python -m pip install -r requirements-build.txt
python build_release.py --out-dir "V2"
```
