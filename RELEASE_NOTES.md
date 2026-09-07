# 0.1.0-rc3 - Public source release

This release publishes the standalone offline patcher source. All 31 Python
files, including build tooling and tests, contain no comments or docstrings.
CLI descriptions remain ordinary runtime strings. Instructions and third-party
license notices are provided in separate documents.

Patch discovery and generated game behavior are unchanged from rc2. The source
was checked for syntax-tree equivalence after removing docstrings, and the
version was advanced for the new source/executable package. All 72 unit tests
pass. The rebuilt standalone binary is verified through complete 440.853 output
construction and comparison against the accepted rc2 output.

## 0.1.0-rc2 - FH6 440.853 compatibility

The offline patcher now passes complete original-file construction on 440.853,
as well as the previously accepted 430.771 build. Both produce 113 discovered
patch actions. On 440.853, the user confirmed save loading and driving during
a monitored run that passed later debugger attachment, three software
breakpoints, three pause/resume cycles, and normal exit.

The rc1 patcher refused the new build without publishing an EXE. The differences
exposed two layout-normalization gaps: incomplete displacement widths reported
for some prefixed SIMD instructions, and static TLS field offsets moving between
builds. Rc2 proves complete RIP displacements from their encoding and discovers
TLS operand identities using the selected EXE's own metadata and register data
flow. Field bounds, access widths, initial values, and alias relationships remain
checked. Unrelated scalar constants and control-flow changes remain visible.

Recognition metadata was regenerated from the previously accepted 430.771
analysis image. No 440.853 address table, build whitelist, replacement code,
reference plaintext, or runtime patch DLL was added. The 430.771 output has
identical patch actions, code, data, helper metadata, and decoded container to
the accepted rc1 output.

All 72 unit tests pass. Native Windows unwind and allocation/detach emulation
checks also pass on the new build. The standalone Windows x64 binary produced
the complete new output with Python environment settings removed and PATH
restricted to Windows System32. Its output is equivalent to the tested source
output, apart from randomized authenticated-container encoding and PE checksum.

The package includes the application, source, instructions, third-party notices,
and SHA-256 checksums. It contains no game files. Windows 10/11 x64 is the target;
other Windows versions and architectures are not qualified. Future compiler or
container changes can still require new support and are refused when validation
fails. See [VALIDATION.md](VALIDATION.md) for evidence and limits.
