include ../../../defines.make

.PHONY: build

# TODO: DON'T change PYTHON_VERSION.
# depends on several additional python packages, that are downloaded with python 3.7.6, and that are placed there
# It won't help to just download them again with python 3.8 and place the modules there,
# because we need the packages that match the build environment, i.e. CentOS 6
# And on CentOS 6, you have to compile python 3.8 by yourself,
# which is now done for 3.7.6, and may or may not be the same procedure for 3.8
# And of course, you can't compile python 3.x right away on CentOS 6,
# so you need to at least compile your own OpenSSL, that again may be required in a different version for 3.8
PYTHON_VERSION = 3.7.6
BUILD_SCRIPTS_DIR = ../../buildscripts/infrastructure/build-nodes/scripts

ifndef NEXUS_ARCHIVES_URL
$(error NEXUS_ARCHIVES_URL is not set)
endif
ifndef NEXUS_USERNAME
$(error NEXUS_USERNAME is not set)
endif
ifndef NEXUS_PASSWORD
$(error NEXUS_PASSWORD is not set)
endif
# ARCHITECTURE needs to be set to i386 or amd64
ifndef ARCHITECTURE
$(error ARCHITECTURE is not set)
endif
ifndef DOCKER_REGISTRY_NO_HTTPS
$(error DOCKER_REGISTRY_NO_HTTPS is not set)
endif
ifeq (i386,$(ARCHITECTURE))
BITNESS_SUFFIX = -32
DOCKER_SRC = $(DOCKER_REGISTRY_NO_HTTPS)/toopher/centos-i386:centos6
LIBCRYPTO_FIX =
else
BITNESS_SUFFIX =
DOCKER_SRC = $(DOCKER_REGISTRY_NO_HTTPS)/centos:6
LIBCRYPTO_FIX = --add-binary '/lib64/libcrypt.so.1:.'
endif

DISTRO = centos-6$(BITNESS_SUFFIX)

BINARY_NAME = cmk-update-agent$(BITNESS_SUFFIX)

build: $(BINARY_NAME)

$(BINARY_NAME): FORCE_SCRIPT_COPY cmk_update_agent.py
	docker build \
	    --build-arg DOCKER_SRC=$(DOCKER_SRC) \
	    --build-arg ARCHITECTURE=$(ARCHITECTURE) \
	    --build-arg DISTRO=$(DISTRO) \
	    --build-arg BRANCH_VERSION=$(BRANCH_VERSION) \
	    --build-arg NEXUS_ARCHIVES_URL=$(NEXUS_ARCHIVES_URL) \
	    --build-arg NEXUS_USERNAME=$(NEXUS_USERNAME) \
	    --build-arg NEXUS_PASSWORD="$(NEXUS_PASSWORD)" \
	    --build-arg PYTHON_VERSION=$(PYTHON_VERSION) \
	    --build-arg BITNESS_SUFFIX=$(BITNESS_SUFFIX) \
	    -f Dockerfile \
	    -t agent-updater-builder-base-$(ARCHITECTURE)-$(BRANCH_VERSION) \
	    .
	docker run \
	    --rm \
	    -u $$(id -u) \
	    -v $(PWD):/build \
	    -w /build\
	    agent-updater-builder-base-$(ARCHITECTURE)-$(BRANCH_VERSION) \
	    /opt/bin/python3 -m PyInstaller ${LIBCRYPTO_FIX} \
	       --clean \
	       --onefile \
	       --name=$(BINARY_NAME) \
	       cmk_update_agent.py \
        && mv dist/$(BINARY_NAME) .

FORCE_SCRIPT_COPY:
	cp $(BUILD_SCRIPTS_DIR)/build_lib.sh build_scripts
	cp $(BUILD_SCRIPTS_DIR)/install-openssl.sh build_scripts
	cp $(BUILD_SCRIPTS_DIR)/install-python.sh build_scripts
	sed -i s/^PYTHON_VERSION=[0-9.]*$$/PYTHON_VERSION=$(PYTHON_VERSION)/ build_scripts/install-python.sh
	sed -i -E "/enable-optimizations|with-lto/d" build_scripts/install-python.sh
