.PHONY: install run test eval demo docker
install:
	python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
run:
	.venv/bin/uvicorn app.main:app --reload --port 8080
test:
	.venv/bin/pytest -q
eval:
	.venv/bin/python -m eval.run_eval --n 600
demo:  ## fresh DB, 800 alerts, play the analyst, export regressions, 400 more alerts
	.venv/bin/python -m scripts.replay --n 800 --reset
	.venv/bin/python -m scripts.seed_corrections
	.venv/bin/python -m scripts.export_regressions
	.venv/bin/python -m scripts.replay --n 400
docker:
	docker compose up --build
