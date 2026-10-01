# MATLAB R2025a P-code decompiler

This tool reconstructs MATLAB-like source from the newer ZIP/OPC-based P-code
format used by MATLAB R2025a on Windows x64. It captures the serialized AST/PVM
records after MATLAB's own reader has decoded them, then renders those records
offline as readable or parseable MATLAB code.

Use it only on P-files you own or are authorized to inspect.

## What it recovers

- Function signatures and ordered inputs and outputs
- Identifiers, literals, operators, calls, and indexing
- Matrices, cells, structures, and field access
- Assignments, command syntax, and expression statements
- `if`, `elseif`, `else`, `for`, `while`, `switch`, `try`, and `catch`
- Nested or local functions
- Embedded source-line positions

It does not reproduce original comments, whitespace, indentation, or redundant
parenthesis choices. Those details are not available in the serialized AST.
The result is a semantic source reconstruction, not a byte-for-byte copy of
the original `.m` file.

## Compatibility

The in-process tracer is intentionally build-specific. This version supports
the analyzed Windows x64 MATLAB R2025a `fe_osp.dll`. Before installing a hook,
it verifies the expected instruction bytes at every patched location. It will
stop with an error on a different DLL instead of applying an unsafe patch.

The Python decoding stage has no third-party dependencies and accepts the
`PCTR0001`, `PCTR0002`, and current `PCTR0003` trace formats.

## Requirements

- Windows x64
- MATLAB R2025a
- A MATLAB-supported C++ compiler; Microsoft Visual C++ 2022 is known to work
- Python 3.10 or newer

Configure the compiler once in MATLAB if necessary:

```matlab
mex -setup C++
```

## Build

Open MATLAB in this directory and run:

```matlab
build_mex
```

This creates `pcode_record_trace.mexw64`. The compiled binary is intentionally
ignored by Git because it is platform- and toolchain-specific.

## Capture a P-file

Call the generic capture function with an input P-file and output trace path:

```matlab
status = capture_pcode_trace("C:\path\to\function_name.p", ...
    "C:\path\to\output\function_name.pctr")
```

The capture step invokes `nargin` to make MATLAB parse the target; it does not
execute the function body. A successful status should show:

```matlab
status.installed
status.recordCount
status.permutationCount
status.callbackRva
status.captureFailed
```

`captureFailed` must be false. Hooks exist only in the current MATLAB process.
The MEX restores the original instructions on `stop`, function cleanup, or MEX
unload. It never changes `fe_osp.dll` on disk.

## Reconstruct source

Create a line-numbered, commented listing:

```powershell
python .\pcode_pseudocode.py .\output\function_name.pctr `
  --output .\output\function_name_listing.m
```

Create parseable MATLAB code with blank lines preserving recovered source-line
positions:

```powershell
python .\pcode_pseudocode.py .\output\function_name.pctr `
  --executable --output .\output\function_name.m
```

The executable mode refuses to emit a file if the trace contains an unhandled
record type or a statement whose source position was not recovered.

Inspect raw record statistics or extract payload strings:

```powershell
python .\analyze_record_trace.py .\output\function_name.pctr
python .\analyze_record_trace.py .\output\function_name.pctr `
  --strings-only --output .\output\function_name_strings.txt
```

## Safety notes

- Save work before using any in-process instrumentation.
- Do not bypass the prologue checks for another MATLAB build.
- Review reconstructed code before running it. Decompilation does not make
  untrusted code safe.

See [Architecture](docs/ARCHITECTURE.md) for the file format, hook locations,
and porting notes.
