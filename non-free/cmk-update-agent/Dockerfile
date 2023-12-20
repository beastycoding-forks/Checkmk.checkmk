ARG DOCKER_SRC
FROM ${DOCKER_SRC}

ARG BITNESS_SUFFIX
ARG BRANCH_VERSION
ARG DISTRO
ARG NEXUS_ARCHIVES_URL
ARG NEXUS_PASSWORD
ARG NEXUS_USERNAME
ARG PYTHON_VERSION

SHELL ["/bin/bash", "-c"]
ENV PATH="/opt/bin:${PATH}"
ENV PYTHON_COMMAND=python3

ARG BUILD_SCRIPTS_DIR
ENV BUILD_SCRIPTS_DIR=${BUILD_SCRIPTS_DIR}
COPY build_scripts/* /opt/

ARG ARCHITECTURE
# Change centos 6 mirrors. Comunity mirrors have been removed.
# This workaround needs to be repeated after yum update
RUN rm -f /etc/yum.repos.d/* \
    && /opt/change-mirrors.sh

# Installation of yum-plugin-ovl is needed to prevent the error:
# Rpmdb checksum is invalid: dCDPT(pkg checksums): libgcc.i686 0:4.4.7-23.el6 - u
# during "yum -y update".
# The "|| true" is needed to prevent an Rpmdb checksum error in this step
# terminating the installation.
# All packages fail for checksum errors on amd64 => "true" is needed
RUN yum clean all \
    && (yum -y install yum-plugin-ovl || true) \
    && yum -y update \
    && rm -f /etc/yum.repos.d/* \
    && /opt/change-mirrors.sh \
    && yum -y install --nogpgcheck \
    ca-certificates \
    curl \
    tar \
    perl \
    perl-IPC-Cmd \
    perl-Test-Simple \
    gcc \
    gcc-c++ \
    zlib-devel \
    bzip2-devel \
    sqlite-devel \
    readline-devel \
    libffi-devel \
    libuuid-devel

# Ensure all our build containers have the jenkins user (with same uid/gid). The non privileged
# jobs will be executed as this user in the container
RUN groupadd -g 1000 jenkins \
    && useradd -m -u 1001 -g 1000 -s /bin/bash jenkins

COPY src /src
RUN /opt/install-packages.sh
