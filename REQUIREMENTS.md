# Offline FH6 patcher requirements

- Discover targets and dependencies from the selected original FH6 EXE and its
  matching original support file, without fixed game RVAs or build whitelists.
- Use input PE metadata, imports, code/data references, control flow, protection
  descriptors, and decoded instructions to establish supported patch locations.
- Produce an actual modified game EXE offline, without a runtime patch DLL,
  reference plaintext, prebuilt replacement EXE, or binary delta.
- Validate uniqueness, dependencies, original bytes, branch destinations,
  overlap, final PE structure, checksum, and output read-back.
- Refuse missing, changed, ambiguous, or unproved discoveries before publishing
  a new output directory. Preserve original files and existing outputs.
- Record hashes for provenance and integrity, never to select patch layouts.
- Bundle application dependencies for the portable Windows 10/11 x64 package.
- Keep Python source, build tooling, and tests free of comments and docstrings.
  Provide usage instructions and third-party license notices as separate files.

## Compatibility evidence

Complete 430.771 and 440.853 pairs have been validated. Recognition uses reviewed
compiler shapes and direct-dependency fingerprints. Supporting two builds does
not prove arbitrary future compiler or container changes will work. See
[VALIDATION.md](VALIDATION.md) for current evidence and limits.
