```
BIP: XXXX
Title: Ladder Script
Author: Defenwycke <defenwycke@icloud.com>
Status: Pre-Draft (wireframe)
Type: Standards Track
Layer: Consensus (soft fork)
Created: 2026-03-16
License: MIT
```

## Status

This is a **wireframe**, not a draft. The earlier full-length draft
surfaced enough load-bearing spec gaps — unspecified creation proof,
prose-only sighash, consensus rules living in `types.h` rather than
the spec — that submission would have been premature.

The intent is to publish a single BIP that normatively references a
standalone `libladder` library (the same model BIP340 uses for
libsecp256k1). Work on extracting `src/rung/` into that library is
ongoing in the implementation. This wireframe will be filled in
section by section once the library boundary is stable.

For the current state of the protocol, read the implementation
directly (`src/rung/`) or interact with it on signet via the engine
at https://ladder-script.org.

## Abstract

*Pending.* One paragraph describing the typed transaction condition
format, the rung/MLSC structure, and the soft-fork activation path
on `nVersion = 4`.

## Copyright

This document is licensed under the MIT License.

## Motivation

*Pending.*

## Design Overview

*Pending.*

## Specification

*Pending.* Will reference `libladder` for the normative wire format,
evaluator, and sighash. The BIP itself defines the consensus
contract; the library defines the bytes.

## Rationale

*Pending.*

## Backwards Compatibility

*Pending.* `nVersion = 4` is anyone-can-spend on non-upgraded nodes,
following the SegWit / Taproot soft-fork pattern.

## Activation

*Pending.*

## Reference Implementation

The reference implementation lives in this repository under
`src/rung/`. The library extraction (`libladder`) is in progress; once
complete, it will be the normative implementation referenced by this
BIP, with the rest of the Bitcoin Core fork carrying only thin
integration shims.

Test vectors and a live signet are available at
https://ladder-script.org.

## Security Considerations

*Pending.*

## Acknowledgements

*Pending.*
