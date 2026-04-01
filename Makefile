.PHONY: run

ifeq ($(OS),Windows_NT)
PYTHON ?= python
else
PYTHON ?= python3
endif

run:
	$(PYTHON) -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
