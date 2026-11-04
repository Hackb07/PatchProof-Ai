.PHONY: build api web test lint demo-scan

build:
	cargo build --workspace

api:
	cargo run -p patchproof-api

web:
	npm --prefix frontend install
	npm --prefix frontend run dev

test:
	cargo test --workspace

lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets -- -D warnings

demo-scan:
	curl -s -X POST localhost:8000/api/scans -H 'Content-Type: application/json' \
		-d '{"repo_url": "fixtures/vuln-app"}' | python3 -m json.tool
