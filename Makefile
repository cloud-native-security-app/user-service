.PHONY: verify fmt clippy test test-integration doc

# Full local verification (same sequence the previous verification script ran).
# test-integration needs Docker (testcontainers); do not replace it with mocks.
verify: fmt clippy test test-integration doc

fmt:
	cargo fmt --check

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test

test-integration:
	cargo test -- --ignored

doc:
	cargo doc --no-deps
