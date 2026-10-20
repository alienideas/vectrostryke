# Phase 4 — Evidence, integrity, signed updates, self-protect, sync

| Component | Role |
|-----------|------|
| `pack_signing.py` | HMAC-SHA256 sign/verify policy packs (dev keys) |
| `evidence_store.py` | Durable Evidence write/read/verify + retention |
| `self_protect.py` | File manifest; healthy vs degraded |
| `sync.py` | Export evidence queue; pull signed packs from inbox |

## Tests

```bash
python3 platform/phase4/tests/test_phase4.py
```

Dev key `platform/phase4/keys/dev.key` — **not for production**.

© VectorStryke
