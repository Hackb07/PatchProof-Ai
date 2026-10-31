.PHONY: install api web test demo-scan lock

install:
	uv sync

lock:
	uv lock

api:
	uv run uvicorn app.main:app --app-dir backend --reload --port 8000

web:
	npm --prefix frontend install
	npm --prefix frontend run dev

test:
	uv run pytest backend/tests -q

demo-scan:
	curl -s -X POST localhost:8000/api/scans -H 'Content-Type: application/json' \
		-d '{"repo_url": "fixtures/vuln-app"}' | python3 -m json.tool
