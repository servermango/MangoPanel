PYTHON ?= python3
HOST ?= 127.0.0.1
CLIENT_PORT ?= 8000
ADMIN_PORT ?= 8001
PORT ?= $(CLIENT_PORT)

.PHONY: dev-init dev-up dev-up-docker dev-hosting-up dev-hosting-down dev-seed dev-agent dev-agent-once dev-smoke dev-hosting-smoke dev-e2e dev-reset dev-down test

dev-init:
	$(PYTHON) scripts/dev_init.py

# Fast path: panel + simulated account stacks (no Docker). Good for UI/API work.
dev-up:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_HOST=$(HOST) MP_CLIENT_PORT=$(CLIENT_PORT) MP_ADMIN_PORT=$(ADMIN_PORT) $(PYTHON) -m mangopanel.app

# Full system in one command: panel + real per-account Docker containers.
dev-up-docker:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_AGENT_MODE=docker MP_PUBLIC_HOST=$(HOST) MP_HOST=$(HOST) MP_CLIENT_PORT=$(CLIENT_PORT) MP_ADMIN_PORT=$(ADMIN_PORT) $(PYTHON) -m mangopanel.app

dev-hosting-up:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_AGENT_MODE=docker MP_PUBLIC_HOST=$(HOST) $(PYTHON) scripts/dev_seed.py
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_AGENT_MODE=docker MP_PUBLIC_HOST=$(HOST) $(PYTHON) scripts/dev_agent.py --apply-all

dev-hosting-down:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_AGENT_MODE=docker $(PYTHON) scripts/dev_agent.py --down-all

dev-seed:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true $(PYTHON) scripts/dev_seed.py

dev-agent:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_AGENT_MODE=simulate $(PYTHON) scripts/dev_agent.py

dev-agent-once:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_AGENT_MODE=simulate $(PYTHON) scripts/dev_agent.py --once

dev-smoke:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_CLIENT_BASE_URL=http://$(HOST):$(CLIENT_PORT) MP_ADMIN_BASE_URL=http://$(HOST):$(ADMIN_PORT) $(PYTHON) scripts/dev_smoke.py

dev-hosting-smoke:
	MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_CLIENT_BASE_URL=http://$(HOST):$(CLIENT_PORT) $(PYTHON) scripts/dev_hosting_smoke.py

dev-e2e:
	$(PYTHON) -m unittest discover -s tests

dev-reset:
	-MP_ENV=development MP_DEV_AUTH_TEST_MODE=true MP_AGENT_MODE=docker $(PYTHON) scripts/dev_agent.py --down-all
	rm -rf user_files
	rm -rf var/dev
	rm -rf /tmp/mangopanel-dev

dev-down:
	@echo "Stop the running dev server with Ctrl-C. Docker compose profile can be stopped with: docker compose -f docker-compose.dev.yml down"

test:
	$(PYTHON) -m unittest discover -s tests
