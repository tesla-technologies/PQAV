# NLnet Restack: component-level post-quantum signing for MPEG-TS (MVP)
## What this is
This MVP provides three command-line tools to secure MPEG-TS streams with post-quantum cryptography. 

- `pqav-keygen` generates ML-DSA-44 key pair in two files. 

- `pqav-sign` reads a ts file, calculates the hash for each video frame and each audio track, signs a list of hashes every 6 frames, and inserts these signatures into the space occupied by null packets.

- `pqav-verify` reads a signed (perhaps tampered) ts file,  recalculates everything, verifies the signatures, and outputs a verdict for each 6-frame interval, as well as an overall verdict.



## What it is not

This MVP is strictly scoped. It does **not** include:

- Live streams, SRT, RIST, network, sockets.

- Multiple programs.

- H.265, AV1, MPEG-2.

- MPEG-1 Layer II, AC-3, E-AC-3, 302M, LATM, other frequencies (only AAC ADTS 48 kHz is supported), multiple audio streams.

- Remultiplexing, changing bitrate, touching PCR.

- ML-DSA-65, hybrid signatures, FN-DSA, BLAKE3.

- Per-frame signing, hash chains, Merkle trees.

- Subtitles, teletext, SCTE-35, AFD, CEA-608/708.

- HSM, PKCS#11, TPM, certificates, CA, revocation.

- Freshness, "live" , drand, challenges, timestamps.

- Chain of custody, re-signers, BISS, encryption.

- GStreamer, browsers, TypeScript, GUI.



## Build

The project requires Rust 1.85 or higher. To compile the optimized binaries:

```bash
cargo build --release
```

The development and measurement environment used was Ubuntu 24.04 (via WSL2), requiring `ffmpeg`, `tsp` (TSDuck), and `python3`.



## Quick check with the sample

A 10-second sample (`firmado_10s.ts`) is included in `testdata/muestra/` along with its public key. You can verify it without installing `ffmpeg` or TSDuck by running:



```bash
./target/release/pqav-verify --pub testdata/muestra/fuente.pub --in testdata/muestra/firmado_10s.ts --quiet
```

**Expected output:** `RESULTADO: AUTENTICO  intervalos=42 autenticos=42  motivos: ninguno`



## Reproduce the tests

To run the full test suite (P1-P12), you need `ffmpeg`, `tsp` (TSDuck), and `python3` installed.

Run the main script from the project root:

```bash
scripts/run_tests.sh
```

It takes about 10 minutes. The results are saved in `results/tests.csv` and backed up with timestamps in `results/runs/`.



## Results

Below is the summary of the test suite (`results/tests.csv`):

| ID | Description | Expected | Obtained | Pass? |
| --- | --- | --- | --- | --- |
| P1 | Intact file | AUTENTICO (0) | AUTENTICO (0) | yes |
| P2 | PID remap | AUTENTICO (0) | AUTENTICO (0) | yes |
| P3 | Remove nulls | AUTENTICO (0) | AUTENTICO (0) | yes |
| P4 | ffmpeg -c copy | n/a | SIN_FIRMAR (3); PID de firmas: no | n/a |
| P5 | Audio changed 1s | RECHAZADO (1), MANIPULADO | RECHAZADO (1), MANIPULADO | yes |
| P6 | Language changed | RECHAZADO (1), MAPA_ALTERADO | RECHAZADO (1), MAPA_ALTERADO | yes |
| P7 | 1 video frame changed | RECHAZADO (1), MANIPULADO | RECHAZADO (1), MANIPULADO | yes |
| P8 | Splice with other session | RECHAZADO (1), EMPALME | RECHAZADO (1), EMPALME | yes |
| P9 | 1s deleted | RECHAZADO (1), HUECO | RECHAZADO (1), HUECO | yes |
| P10 a-b| Signatures removed | SIN_FIRMAR (3) | SIN_FIRMAR (3) | yes |
| P10c| Sigs removed (no expect) | SIN_FIRMAR (0) | SIN_FIRMAR (0) | yes |
| P11 | Different key | RECHAZADO (1), FIRMA_INVALIDA | RECHAZADO (1), FIRMA_INVALIDA | yes |
| P12 | Corrupt signature | RECHAZADO (1), FIRMA_INVALIDA | RECHAZADO (1), FIRMA_INVALIDA | yes |
||||



*Null substitution:* Yes, it maintains the packet count, with 20 appended packets at the end of the file representing the final anchor.



## Measurements

| Metric | Value | 
|---|---|
| ML-DSA-44 signature size | 2420 B |
| COSE size per anchor (mean) | ≈ 3192 B (2752–3612 B) |
| Sig bytes per frame (video only) | ≈ 458 B/frame |
| Sig bytes per frame (video + audio) | ≈ 532 B/frame |
| Audio cost per frame | ≈ 74 B/frame |
| Bytes in TS per frame | ≈ 558 B/frame |
| Signatures PID bitrate | 111.7 kb/s |
| Insertion delay (p50 / p99) | 20.7 ms / 53.4 ms |
| Signing time per anchor (p50 / p99) | 334 µs / 1901 µs |
| Verification time per anchor (p50 / p99) | 56 µs / 96 µs |
| Total verification time (60s file) | 0.13 s |
| Appended packets at the end | 20 packets |
|||


**Machine specs:** AMD Ryzen 5 7520U with Radeon Graphics (8 threads), 7.4Gi RAM, Linux 6.6.87.2-microsoft-standard-WSL2 (Ubuntu 24.04), rustc 1.99.1 (release build).



## Command-line usage

**Key generation:**

`pqav-keygen --out <prefix> [--force]`



**Signer:**

`pqav-sign --key <file.seed> --in <file.ts> --out <file.ts> [--anchor-pid 0x1FF0] [--bitrate 8000000] [--stats <file.json>] [--debug-unit <comp:pts>]`



**Verifier:**

`pqav-verify --pub <file.pub> --in <file.ts> [--anchor-pid 0x1FF0] [--no-expect-signed] [--json <file.json>] [--quiet] [--debug-unit <comp:pts>]`



**Exit codes:** 

- `0`: AUTENTICO (or SIN_FIRMAR with `--no-expect-signed`).

- `1`: RECHAZADO.

- `2`: ERROR_ENTRADA (Usage error, missing files, non-compliant TS).

- `3`: SIN_FIRMAR (Missing signatures).



## Format

Please refer to [`FORMATO.md`](FORMATO.md) for the detailed technical specification of the byte structures, payloads, and protocols.



## Limitations

- It is a recorded file, not a live stream. It does not assert when it was recorded.

- An attacker can remove all signatures. The verifier detects this (SIN_FIRMAR) only because it expects signatures by default. With `--no-expect-signed` it only warns (test P10c).

- Identical frames from another signed session have the same hash. Splicing is detected by `stream_id` (A5) and `prev` (A7, prev of the first anchor in the other session is not the hash of the previous anchor). The counter does not detect it: in P8 it continues in order.

- The private key is stored in a plain file without any protection.

- Only H.264 and AAC at 48 kHz, single program.

- The signature is deterministic to allow reproducible tests. In the actual project design, the device signs with the hedged randomized variant. Both are valid ML-DSA and the verifier cannot distinguish between them.

- Remultiplexing with `ffmpeg -c copy` discards the private signature PID, leaving the file unsigned (demonstrated in test P4).





<br><br>

## Licence

The code is dual-licensed under MIT OR Apache-2.0. Documentation and data are licensed under CC BY 4.0. See `LICENSE-MIT` and `LICENSE-APACHE` for details.

---

© 2026 Tesla Technologies & Software S.L. All rights reserved.
