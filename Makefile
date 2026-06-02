# CLOUDRANGE Makefile.
# Mock targets run fully offline (no AWS account, no network). Use PY to point
# at a specific interpreter, e.g.  make test PY=python3.11
PY ?= python

.PHONY: help install test validate enumerate privesc attack detect \
        report tf-init tf-validate tf-fmt tf-plan tf-destroy docker clean

help:  ## Show this help.
	@echo "CLOUDRANGE -- targets:"
	@echo "  make install      Install deps + the cloudrange CLI"
	@echo "  make test         Run the offline test suite"
	@echo "  make enumerate    List the (mock) environment"
	@echo "  make privesc      Find all privesc paths (mock)"
	@echo "  make attack       Run the attack chain (mock)"
	@echo "  make detect       Audit + print findings (mock)"
	@echo "  make report       Write SARIF + Markdown to ./out/"
	@echo "  make validate     terraform validate + fmt check"
	@echo "  make docker       Build the Docker image"

install:  ## Install dependencies and the CLI.
	$(PY) -m pip install -r requirements.txt
	$(PY) -m pip install -e .

test:  ## Run the offline test suite.
	$(PY) -m pytest -q

enumerate:  ## Enumerate the bundled vulnerable fixture.
	$(PY) -m cloudrange enumerate --mock

privesc:  ## Find every privilege-escalation path (mock).
	$(PY) -m cloudrange privesc --mock

attack:  ## Run the attack chain end-to-end (mock).
	$(PY) -m cloudrange attack --mock

detect:  ## Read-only audit -> findings to stdout (mock).
	$(PY) -m cloudrange detect --mock

report:  ## Write SARIF + Markdown reports to ./out/.
	@mkdir -p out
	$(PY) -m cloudrange detect --mock --sarif-out out/findings.sarif --md-out out/findings.md
	@echo "Wrote out/findings.sarif and out/findings.md"

# --- Terraform (requires the terraform binary on PATH) -------------------- #
validate: tf-validate tf-fmt  ## terraform validate + fmt check.

tf-init:  ## terraform init (downloads providers).
	cd terraform && terraform init -input=false

tf-validate:  ## terraform validate (no AWS creds needed).
	cd terraform && terraform init -backend=false -input=false >/dev/null && terraform validate

tf-fmt:  ## terraform fmt check.
	cd terraform && terraform fmt -check -recursive

tf-plan:  ## terraform plan (needs AWS creds; throwaway account only).
	cd terraform && terraform plan

tf-destroy:  ## terraform destroy -- ALWAYS run this when finished.
	cd terraform && terraform destroy

docker:  ## Build the Docker image.
	docker build -t cloudrange:latest .

clean:  ## Remove build/output artifacts.
	rm -rf out build dist *.egg-info .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
