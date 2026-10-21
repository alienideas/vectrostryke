# VectorStrykeEngine

**C++17 engine** for VectorStryke (open source, no proprietary dependencies).

| Phase | Status |
|-------|--------|
| E0–E1 | Core, config, ResponseMode, C API, CLI |
| **E2** | Heuristic detect + finding callback |
| **E3** | Path scan + quarantine-first |
| **E4** | Signature DB + matcher (optional ASM stub) |

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DVS_ENGINE_BUILD_TESTS=ON
cmake --build build -j
cd build && ctest --output-on-failure
```

## CLI

```bash
./build/vs-engine version|status|start|stop
./build/vs-engine detect <path>
./build/vs-engine scan <path>
./build/vs-engine load-sigs data/signatures.vdb
```

© VectorStryke
