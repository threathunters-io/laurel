SHELL := /bin/bash
LOCAL_DEV_CONTAINER_NAME = "docker-laurel"
LOCAL_DEV_WORKDIR = "/usr/src/laurel"
RUST_VERSION := 1.52

dargo: ## Run a cargo command inside the container
	@# If the dargo container does not exist, create it
	@if [ -z $(shell docker ps --format "{{.ID}}" --filter "name=$(LOCAL_DEV_CONTAINER_NAME)") ]; then make dargo-run-container; fi
	@# Run a command inside the container
	docker exec -ti $(LOCAL_DEV_CONTAINER_NAME) cargo $(COMMAND)

dargo-clean-container:
	@echo 'cleaning local development container'
	@docker rm -fv $(LOCAL_DEV_CONTAINER_NAME)

dargo-run-container: ## Runs a Rust container with the pwd (i.e. current folder) bind-mounted to it
	@if [ ! -z $(shell docker ps --format "{{.ID}}" --filter "name=$(LOCAL_DEV_CONTAINER_NAME)") ]; then make dargo-clean-container; fi
	@echo 'running interactive rust container for local development'
	@docker run \
	--detach \
	--tty \
 	--name $(LOCAL_DEV_CONTAINER_NAME) \
 	--workdir $(LOCAL_DEV_WORKDIR) \
 	--mount type=bind,source="$(shell pwd)",target=$(LOCAL_DEV_WORKDIR) \
 	rust:$(RUST_VERSION)
