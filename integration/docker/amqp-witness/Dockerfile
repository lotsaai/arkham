FROM python:3-slim@sha256:db3231d3fce4c59182f8364dbec08b8bad4fdfca673dfb226f3c9e77b6b48cd2

# A Debian revision pin breaks when trixie drops that build.
# hadolint ignore=DL3008
RUN apt-get update -qq \
    && apt-get install -qq -y --no-install-recommends tcpflow \
    && rm -rf /var/lib/apt/lists/*
