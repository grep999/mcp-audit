.PHONY: check test install service

check: test
	python3 -m py_compile cli/*.py api/*.py

test:
	@for f in tests/test_*.py; do python3 $$f || exit 1; done

install:
	pip install -e .

service:
	python3 -m api.service