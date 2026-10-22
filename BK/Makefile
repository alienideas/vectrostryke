.PHONY: all build test lint clean ci

all: build

build:
	@mkdir -p build && cd build && cmake .. && $(MAKE) -j$$(nproc 2>/dev/null || echo 2)

test:
	@./scripts/ci/test.sh

lint:
	@./scripts/ci/lint.sh

ci:
	@./scripts/ci/run_all.sh

clean:
	rm -rf build bin dist
