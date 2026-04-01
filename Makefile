.PHONY: run

run:
	python3 -m uvicorn main:app --host 127.0.0.1 --port 8000 --reload
