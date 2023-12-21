# Copyright (C) 2019 Checkmk GmbH - License: Checkmk Enterprise License
# This file is part of Checkmk (https://checkmk.com). It is subject to the terms and
# conditions defined in the file COPYING, which is part of this source code package.

include ../../defines.make

# It is used from top-level Makefile and this makefile as an intermediate step.
# We should end up with one central place to care for packaging our files
# without the need to have shared logic between like this.
include $(REPO_PATH)/artifacts.make

PROTOBUF_PATH       := $(REPO_PATH)/omd/build/intermediate_install/protobuf-3.20.1-library
PROTOC              := $(PROTOBUF_PATH)/bin/protoc
PROTO_PATH          := $(REPO_PATH)/non-free/cmc-protocols/protocols
PROTO_PYTHON_OUT    := $(REPO_PATH)/non-free/cmc-protocols/cmc_proto

.PHONY: protobuf-files

protobuf-files: $(CMC_PROTO_MODULES)

$(PROTOC):
	$(MAKE) -C $(REPO_PATH)/omd protobuf-build-library

$(REPO_PATH)/.venv:
	$(MAKE) -C $(REPO_PATH) .venv

$(PROTO_PYTHON_OUT)/%_pb2.py: $(PROTO_PATH)/checkmk/cmc/%.proto $(PROTOC) $(REPO_PATH)/.venv
	$(PROTOC) \
        --plugin=protoc-gen-mypy=$(REPO_PATH)/.venv/bin/protoc-gen-mypy \
        --proto_path=$(PROTO_PATH)/checkmk/cmc \
        --python_out=$(PROTO_PYTHON_OUT) \
        --mypy_out=$(PROTO_PYTHON_OUT) \
        $<
	sed -ri \
		-e 's/from (cycletime)/from cmc_proto.\1/g' \
		-e 's/import (cycletime).*$$/import cmc_proto.\1 as \1/g' \
		$@ $@i
