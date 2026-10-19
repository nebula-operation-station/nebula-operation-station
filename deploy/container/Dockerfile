# SPDX-License-Identifier: AGPL-3.0-or-later
# One image with the four binaries (decision 5 of the M10 plan). The build
# context holds the binaries (GoReleaser's dockers step, or `make build`
# and `docker build -f deploy/container/Dockerfile bin/`). compose.yaml
# runs executor, server and discovery as three containers from it, each
# with its own fixed UID, as the systemd units do with OS users.
FROM debian:12-slim

# nmap for discovery, with the raw-socket capability as a file capability:
# it only takes effect in a container that keeps CAP_NET_RAW in its
# bounding set (only the discovery container does).
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap libcap2-bin ca-certificates \
 && setcap cap_net_raw=eip /usr/bin/nmap \
 && apt-get purge -y libcap2-bin && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# Fixed IDs: the executor authorizes callers by UID (SO_PEERCRED), so the
# server and the admin must have the same UIDs in every container.
RUN groupadd --system --gid 10010 nebula-rpc \
 && groupadd --system --gid 10001 nebula-executor \
 && groupadd --system --gid 10002 nebula-server \
 && groupadd --system --gid 10003 nebula-discovery \
 && groupadd --gid 10100 nebula-admin \
 && useradd --system --uid 10001 --gid 10001 --groups nebula-rpc --home-dir /var/lib/nebula/executor --shell /usr/sbin/nologin nebula-executor \
 && useradd --system --uid 10002 --gid 10002 --groups nebula-rpc --home-dir /var/lib/nebula/server --shell /usr/sbin/nologin nebula-server \
 && useradd --system --uid 10003 --gid 10003 --home-dir /var/lib/nebula/discovery --shell /usr/sbin/nologin nebula-discovery \
 && useradd --uid 10100 --gid 10100 --groups nebula-rpc --create-home --shell /bin/bash nebula-admin \
 && install -d -m 0755 /var/lib/nebula /etc/nebula \
 && install -d -m 0700 -o nebula-executor -g nebula-executor /var/lib/nebula/executor /var/lib/nebula/executor/keys \
 && install -d -m 0750 -o nebula-server -g nebula-server /var/lib/nebula/server \
 && install -d -m 0755 /var/lib/nebula/discovery \
 && install -d -m 0750 -o nebula-server -g nebula-discovery /var/lib/nebula/discovery/jobs \
 && install -d -m 0750 -o nebula-discovery -g nebula-server /var/lib/nebula/discovery/results \
 && install -d -m 0750 -o nebula-executor -g nebula-rpc /run/nebula

COPY nebula nebula-server nebula-executor nebula-discovery /usr/bin/

# No default command: compose.yaml names one per container.
USER 65534:65534
