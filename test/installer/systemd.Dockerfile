# Debian 13 with systemd as PID 1, for the real-systemd installer test
# (test/installer/systemd.test.mjs). Build it before running that test:
#   docker build --pull -t orbit-installer-systemd:debian13 -f test/installer/systemd.Dockerfile test/installer
# Node 24 lives in a versioned directory and is found through /usr/local/bin/node, like a
# distribution package behind /usr/bin/node, so the test can move it as a Node upgrade would.
FROM node:24-bookworm-slim AS node

FROM debian:trixie
ENV container=docker DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends systemd systemd-sysv ca-certificates procps \
  && rm -rf /var/lib/apt/lists/* \
  && systemctl mask systemd-firstboot.service systemd-logind.service getty.target console-getty.service \
  && systemctl set-default multi-user.target
COPY --from=node /usr/local/bin/node /opt/node-24/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /opt/node-24/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /opt/node-24/bin/npm \
  && ln -s /opt/node-24/bin/node /usr/local/bin/node \
  && ln -s /opt/node-24/bin/npm /usr/local/bin/npm \
  && node --version && npm --version
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
