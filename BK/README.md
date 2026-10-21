# VectorStrykeBK (C/C++)

Complementary production-style automation backup for VectorStryke.

- **Language:** C11 core · CMake · optional OpenSSL
- **Platforms:** Windows · Linux · macOS

## Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DVSBK_BUILD_TESTS=ON
cmake --build build -j
cd build && ctest --output-on-failure
./vsbk-agent /path/to/data
```

## Complementarity

- Skips quarantine paths by default
- Optional VectorStryke webhook on backup complete

Apache-2.0 · © VectorStryke
