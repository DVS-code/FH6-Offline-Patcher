# Validation - 0.1.0-rc3

## Public-source packaging

All 31 Python files, including tests and build tooling, have zero comment tokens
and zero docstrings. The removal was checked with Python's tokenizer and AST.
Executable syntax was preserved, with module-docstring CLI descriptions retained
as ordinary string arguments; the patcher version was then advanced to rc3.
All 72 unit tests pass.

Rc3 changes source presentation and package version. The rc2 gameplay acceptance
below remains the behavior baseline. The rebuilt rc3 binary passed complete 113-action offline construction with
Python settings removed and PATH restricted to System32. Its output has the
same native code, data, helper metadata, patch actions, and authenticated
container plaintext as the accepted rc2 output. Only randomized container
encoding and the dependent PE checksum differ. No new gameplay run was needed
for this source-presentation change.

Rc3-generated 440.853 output SHA-256:
`ad3c546a3b6319fcd9be056fb95909d3a02370890388e902d58e178b9a35ab9d`.

Rc3 Windows patcher SHA-256:
`fbbff662b05730409c62497db02f7409fb814c39199de855a23fb620ebc97ac9`.

## Historical rc2 validation - 0.1.0-rc2, September 7, 2026

## Complete original-file tests

| FH6 build | Reconstruction | Patch actions | Gameplay/debugger evidence |
| --- | --- | --- | --- |
| 430.771 | 167,918 startup records; 412 dynamic bodies; 5,268 native records | 113 | Previously passed save loading, driving, later attachment, breakpoints, pause/resume, normal exit. Rc2 output equivalence verified. |
| 440.853 (6.440.853.0) | 167,992 startup records; 413 dynamic bodies; 5,272 native records | 113 | User confirmed save loading and driving during the monitored rc2 source-output test; debugger and normal-exit checks passed. |

The rc1 binary refused 440.853 before publishing any game output. Its short
anchors all matched, but strict function/dependency fingerprints caught layout
differences. Rc2 fixes full RIP displacement normalization and discovers static
TLS field operands from input metadata and data flow. All 102 reviewed roles and
their dependencies validate. Recognition metadata was regenerated from the
accepted 430.771 image; the newer image was used to test those rules.

Input SHA-256 values record provenance and do not select patches:

- 430.771 EXE: `b62b5ec1933b2d11a6b80941ae0d2b38c4a5aaefdd880e487453d178081d7b44`
- 430.771 support: `2c9d80a3c6afb142e0562e6bddbcc90b167a52241a3ad8290d8aa4050c41bac6`
- 440.853 EXE: `fec4a63cdead26f6528564f0e33c3d7fd02cd887337ed6e1aeaca79eb2843fcd`
- 440.853 support: `081f7511b5d05d87fd9a419f7ec411e80e8705f8590c52d9c0f3beca34aa6868`

## 440.853 gameplay and debugger test

The isolated game launched normally. Windows DebugActiveProcess attached at
60.093 seconds and remained attached. Three temporary software breakpoints were
delivered and restored; three three-second pause/resume cycles succeeded. All
113 sampled patch sites remained intact. There were no second-chance exceptions.
The user reported: "Save loads and driving works." The game exited with code 0
at 204.203 seconds after a normal window-close request. No patch DLL was loaded.

This gameplay confirmation is user-reported, accompanied by the debugger trace;
it is not an automated visual-driving assertion. Source-generated tested EXE:
`584355a4081dc29f615481d12954c1164c5d839a5517295fb04a988a3ad5f23d`.

## Standalone application and regression checks

- All 72 source unit tests pass, including moved SIMD displacements, unrelated
  scalar changes, TLS bounds and initial values, wrong module indices, register
  clobbers, branch joins, pointer truncation, stores, and field alias changes.
  Existing parser, authentication, ambiguity, branch, import, patch preimage,
  overlap, transactional publication, and input-lock checks also pass.
- On 440.853, native Windows RtlVirtualUnwind restored the frame at every helper
  instruction boundary. Emulation verified allocation success/null results,
  lock release, native cookie checks, register restoration, and detach-query
  cancellation through the existing failure continuation.
- The packaged EXE, copied alone outside the workspace, completed all 113
  actions with Python settings removed and PATH restricted to System32.
- The packaged output and tested source output have identical actions, native
  code, ordinary data, helper metadata, and authenticated container plaintext.
  Randomized container encoding and its dependent PE checksum differ by design.
- The regenerated 430.771 output is equivalent on the same criteria to the
  accepted rc1 source output. Gameplay on old assets was not rerun after Steam
  updated the installed game.

Rc2 patcher SHA-256:
`c4def5cc535cad875736515d37d71f29edb3d3b09246d29ceabe039a909c7da7`.

Standalone-generated 440.853 EXE SHA-256:
`4626056625fa7fec260af07f378fdae9e933502f8db928e5126650c162183f72`.

## Compatibility limits

The portable package targets Windows 10/11 x64 and bundles Python, Tk,
disassembly, cryptography, and Visual C++ runtime dependencies. The restricted
environment test ran on the existing Windows host, not a separate clean PC or
every supported Windows revision. Windows on ARM, 32-bit Windows, and older
Windows are not qualified. Running FH6 still requires its own complete matching
installation and normal platform dependencies.

Two complete builds now have evidence. The older 420.696 EXE was refused when
paired with the available newer support file; its matching original support
file was unavailable. Arbitrary future builds are not guaranteed. Recognition
checks supported compiler shapes, control flow, direct dependencies, and proved
storage relationships; it does not establish arbitrary program equivalence or
the semantic identity of every equal-initialized global/TLS field.

Missing, changed, ambiguous, or unproved discoveries stop output publication.
EXE/support association uses independent PE boundaries and the complete patch
plan; it is not a cryptographic binding between the original files. No game
files, captured plaintext, runtime patch DLL, replacement EXE, or build-specific
RVA table are shipped in this package.
