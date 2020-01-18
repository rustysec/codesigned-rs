CodeSigned
==========
[![Build Status](https://github.com/rustysec/codesigned-rs/workflows/Build/badge.svg)](https://github.com/rustysec/codesigned-rs/actions)

A Rust library for checking digital signatures on Windows.

Code signing allows authors to certify the origin of their work, and end users
to verify the integrity of executables before running them. Microsoft has a lot
of documentation around the topic [here](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools).

## Background
Code signing on windows comes in two basic flavors:

* Embedded Signatures
* Signature Catalogs

When using **embedded signatures** the executable has the x509 data attached to it and integrity
checks can be run directly against that file.

**Signature catalogs** are where things get a little more complicated. Instead of embedding certificate
data in all of the thousands upon thousands of binaries included in windows, the concept of a catalog was
developed. This manifests itself in the form of many catalog files containing hash information of binaries
on the system. This catalog is, in turn, signed using an *embedded signature*. Applications who's hash(es)
appear in the catalog are treated as though they share the embedded signature of the catalog file.

## Example Usage
**Cargo.toml**:
```toml
[dependencies]
codesigned = { git = "https://github.com/rustysec/codesigned-rs" }
```

**rust code**:
```rust
use codesigned::CodeSigned;

let signature = CodeSigned::new(r"c:\windows\system32\notepad.exe")?;
```

## Contributions
Contributions are always welcome! If you find a bug or a missing feature, please file an issue.
