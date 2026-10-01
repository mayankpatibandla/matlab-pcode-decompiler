# Architecture and trace format

## Processing pipeline

```text
.p ZIP/OPC package
        |
        v
MATLAB fe_osp reader and record decoder
        |
        v
pcode_record_trace MEX
        |
        v
PCTR0003 decoded-record trace
        |
        +--> analyze_record_trace.py
        |
        `--> pcode_pseudocode.py --> MATLAB-like source
```

The P-file remains unchanged. The tracer observes records after the shipping
MATLAB decoder has already processed their per-record transformations.

## Container

The newer P-file is a ZIP/OPC package containing `/pcode/binary`. Its binary
payload begins with a four-byte big-endian field element. The multiplicative
inverse of that value modulo `0xfffffffd` gives the length of the following
metadata blob. The serialized PVM stream follows that blob.

Records contain an XOR-masked opcode. Negative record encodings carry a
base-128 value and may carry an attached byte payload. Rendering the stream as
an AST also requires the aggregate-child permutations applied by MATLAB while
it constructs lists.

## R2025a hook points

The current Windows x64 build uses RVAs relative to `fe_osp.dll`:

| Purpose | RVA |
| --- | ---: |
| Record decoder | `0x7e990` |
| First aggregate handler | `0xac0c0` |
| Permutation callback | `0xbbc50` |

The MEX checks 15 expected instruction bytes at the decoder and permutation
callback before patching. Each detour uses a trampoline containing the original
instructions followed by an absolute jump back into `fe_osp.dll`.

The aggregate handler exposes the permutation factory. For each aggregate, the
tracer records every source-index to destination-index placement. This is
required to recover argument order, function signatures, matrix contents, and
statement order correctly.

## PCTR0003 layout

All multibyte values use the host's little-endian representation.

```text
8 bytes   magic: "PCTR0003"
uint64    record count

repeated record count times:
    uint8     decoded record type
    uint8     XOR mask
    uint16    flags; bit 0 means payload present
    uint32    decoded raw value
    uint32    payload length
    byte[]    payload

uint64    permutation-event count

repeated permutation-event count times:
    uint64    owning record index
    uint32    permutation mode
    uint32    aggregate item count
    uint32    placement count
    repeated placement count times:
        uint32    source index
        uint32    destination index
```

## Renderer behavior

`pcode_pseudocode.py` interprets records as a stack machine, applies captured
permutations to aggregate nodes, and associates statements with source-line
positions. Its default output is commented for conservative inspection.
`--executable` emits real MATLAB statements only when all encountered record
types and statement positions are resolved.

## Porting to another MATLAB build

Do not reuse the existing RVAs blindly. A port requires locating the equivalent
record decoder, aggregate handler, and permutation callback in that build's
`fe_osp.dll`, then updating both RVAs and expected prologue bytes. Revalidate:

1. Record counts are stable across repeated parses.
2. No capture failure is reported.
3. Every aggregate event has the expected number of placements.
4. Known, authorized source samples reconstruct with correct child ordering.
5. Hooks uninstall cleanly and the MATLAB process remains stable.
