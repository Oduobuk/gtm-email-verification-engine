.PHONY: test benchmark serve clean

test:
	pytest tests/ -v

benchmark:
	python3 benchmarks/benchmark_throughput.py

serve:
	uvicorn gtm_verifier.api:app --host 0.0.0.0 --port 8080 --workers 4

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .pytest_cache build dist *.egg-info
