# VectorStryke BK — Backup (C11)

Complementary, quarantine-aware backup agent.

```bash
cmake -B build -DVSBK_BUILD_TESTS=ON
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Env: `VSBK_STORAGE`, `VSBK_RESPECT_QUARANTINE`, `VECTORSTRYKE_HOOK_URL`.
