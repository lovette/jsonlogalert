VENVNAME := $(shell basename $(CURDIR))
VENVROOT := ${HOME}/.virtualenvs
VENVDIR := ${VENVROOT}/${VENVNAME}

ERROR_NO_VIRTUALENV = $(error Python virtualenv is not active, activate first)
ERROR_ACTIVE_VIRTUALENV = $(error Python virtualenv is active, deactivate first)

############################
## Help

.PHONY: help
.DEFAULT_GOAL := help
help:
	@printf 'Usage: make [VARIABLE=] TARGET\n'
	@awk 'BEGIN {FS = ":.*##";} /^[a-zA-Z1-9_-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)


############################
##@ Python virtualenv

.PHONY: virtualenv
virtualenv:  ## Create venv directory and install pip
ifdef VIRTUAL_ENV
	$(ERROR_ACTIVE_VIRTUALENV)
endif
	python3 -m venv --system-site-packages --prompt ${VENVNAME} ${VENVDIR}
	${VENVDIR}/bin/python3 -m pip install --require-virtualenv --upgrade --no-cache-dir pip pip-tools wheel
	@echo
	@echo "EMPTY Python virtualenv named '${VENVNAME}' created in ${VENVROOT}"
	@echo "To activate: source ${VENVDIR}/bin/activate"
	@echo "To install packages: 'make install' or 'make install-dev'"

.PHONY: rmvirtualenv
rmvirtualenv:  ## Remove venv and Python cache directories
ifdef VIRTUAL_ENV
	$(ERROR_ACTIVE_VIRTUALENV)
endif
	rm -rf ${VENVDIR}
	find . -type d -name __pycache__ -print -exec rm -rf {} +


############################
##@ Python install

.PHONY: install
install:  ## Install project packages and script
	python3 -m pip install --require-virtualenv --upgrade -r requirements.txt .

.PHONY: install-dev
install-dev:  ## Install project packages and script for development
	python3 -m pip install --require-virtualenv --upgrade -r requirements.txt -r requirements-dev.txt -e .


############################
##@ Python requirements
#
# Use pip-compile to generate requirements[-dev].txt based on `pyproject.toml` dependencies.
# https://pypi.org/project/pip-tools/
#
# To update requirements, run:
#
#    make requirements
#
# To install and update packages, run:
#
#   make pip-sync
# 	-or-
#   make pip-sync-dev

requirements.txt: pyproject.toml
ifndef VIRTUAL_ENV
	$(ERROR_NO_VIRTUALENV)
endif
	python3 -m piptools compile --upgrade --strip-extras --resolver=backtracking --quiet -o requirements.txt pyproject.toml

requirements-dev.txt: requirements.txt
ifndef VIRTUAL_ENV
	$(ERROR_NO_VIRTUALENV)
endif
	python3 -m piptools compile --upgrade --strip-extras --resolver=backtracking --quiet --extra dev --constraint requirements.txt -o requirements-dev.txt pyproject.toml

.PHONY: requirements
requirements: requirements-dev.txt  ## Generate requirements[-dev].txt based on `pyproject.toml` dependencies.

.PHONY: pip-sync
pip-sync: requirements.txt  ## Generate requirements and synchronize packages
ifndef VIRTUAL_ENV
	$(ERROR_NO_VIRTUALENV)
endif
	python3 -m piptools sync requirements.txt

.PHONY: pip-sync-dev
pip-sync-dev: requirements-dev.txt  ## Generate requirements and synchronize packages for development
ifndef VIRTUAL_ENV
	$(ERROR_NO_VIRTUALENV)
endif
	python3 -m piptools sync requirements-dev.txt requirements.txt


############################
##@ Python Ruff

.PHONY: ruffcheck
ruffcheck:  ## Run Ruff on project files
ifndef VIRTUAL_ENV
	$(ERROR_NO_VIRTUALENV)
endif
	ruff check src

.PHONY: ruffclean
ruffclean:  ## Clear Ruff caches
ifndef VIRTUAL_ENV
	$(ERROR_NO_VIRTUALENV)
endif
	ruff clean


############################
##@ Build

install.sh: $(wildcard makeinstallsh/*.sh)
	makeinstallsh/make.sh > install.sh

man/jsonlogalert.1: src/jsonlogalert/__main__.py
ifndef VIRTUAL_ENV
	$(ERROR_NO_VIRTUALENV)
endif
	click-man jsonlogalert

.PHONY: extras
extras: install.sh man/jsonlogalert.1 ## Generate extra man pages and install script

.PHONY: distclean
distclean:  ## Delete build files, python cache and package build artifacts
	rm -rf build
	rm -rf dist
	rm -rf src/*.egg-info
	rm -rf .ruff_cache
	find . -type d \( -name __pycache__ \) -print -exec rm -rf {} +

############################
##@ Podman test container

.PHONY: podman-build
podman-build: ## Build podman image
	podman build -t jsonlogalert -f Dockerfile .

.PHONY: podman-execsh
podman-execsh: ## Exec shell inside running podman
	podman run --rm -it --entrypoint bash jsonlogalert

.PHONY: podman-build-dev
podman-build-dev: ## Build podman image
	podman build -t jsonlogalert-dev -f Dockerfile-dev .

.PHONY-dev: podman-execsh-dev
podman-execsh-dev: ## Exec shell inside running podman
	podman run --rm -it --entrypoint bash jsonlogalert-dev

.PHONY: podman-build-install
podman-build-install: ## Build podman image
	podman build -t jsonlogalert-install -f Dockerfile-install --ignorefile Dockerfile-install.ignore .

.PHONY-install: podman-execsh-install
podman-execsh-install: ## Exec shell inside running podman
	podman run --rm -it --entrypoint bash jsonlogalert-install
