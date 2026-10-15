# SecureVault container format (version 1)

All integers are big-endian.

| Offset | Size | Field | Description |
|---|---|---|---|
| 0 | 4 | `magic` | ASCII `SVLT` |
| 4 | 1 | `version` | `1` |
| 5 | 4 | `chunk_size` | Plaintext bytes per chunk, 1 to 16,777,216 |
| 9 | 2 | `wrapped_key_len` | Length of the RSA-wrapped session key (256, 384 or 512 for 2048/3072/4096-bit keys) |
| 11 | *wrapped_key_len* | `wrapped_key` | 32-byte AES session key encrypted with RSA-OAEP (MGF1-SHA256, SHA-256, no label) |
| 11 + *wrapped_key_len* | 8 | `nonce_prefix` | Random per-file prefix |
| after header | variable | `chunks` | One or more encrypted chunks |

The **header** is every byte from offset 0 through the end of `nonce_prefix`.

## Chunks

Plaintext is split into pieces of `chunk_size` bytes; the last piece may be shorter, and an empty file produces a single empty chunk. Chunk *i* (starting at 0) is:

```
ciphertext_i || tag_i  =  AES-256-GCM-Encrypt(
    key   = session_key,
    nonce = nonce_prefix || uint32_be(i),     # 12 bytes
    aad   = header || final_flag,             # final_flag = 0x01 on the last chunk, else 0x00
    plaintext = piece_i)
```

Each encrypted chunk is `len(piece) + 16` bytes. Every chunk except the last is exactly `chunk_size + 16` bytes.

If the plaintext length is an exact multiple of `chunk_size`, the last full chunk is the final chunk; no additional empty chunk is written.

## Why this is tamper-evident

| Attack | Why it fails |
|---|---|
| Flip a bit anywhere | GCM tag mismatch for that chunk (or the header, via AAD) |
| Truncate at a chunk boundary | The new last chunk was encrypted with `final_flag = 0`, so verifying it as final fails |
| Append data | Extra bytes change the final chunk's ciphertext (tag fails); appended whole chunks make the old final chunk verify with `final_flag = 0`, which fails |
| Reorder or duplicate chunks | Nonce includes the chunk index, so tags no longer verify |
| Edit `chunk_size` or other header fields | Header is bound into every tag via AAD |

## Limits

- At most 2^32 chunks per file (32-bit counter): 256 TiB at the default chunk size.
- The format does not hide the file length (within a chunk) or the chunk size.

## Reference decryption procedure

1. Parse and validate `magic`, `version`, `chunk_size`, `wrapped_key_len`; reject otherwise.
2. Unwrap `session_key` with RSA-OAEP; require 32 bytes.
3. Read chunks of `chunk_size + 16` bytes, looking one read ahead to determine which chunk is final.
4. Verify and decrypt each chunk with the nonce and AAD above. Abort on the first failure.
5. Commit output only after the final chunk verifies.
