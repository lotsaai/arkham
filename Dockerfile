# Runtime-only image: the binary is built once in CI (amd64 + arm64) and
# copied in here; the container never compiles.
#
# BIN_DIR is where the binary sits in the build context. CI builds from the
# repository root and passes target/release. The release workflow unpacks the
# dist tarball into a context that holds the binary at its root, so the default
# is `.`.
#
# bare:libcxx-udev-ssl provides glibc, libc++, libssl, libudev and CA roots.
# libudev is a hard runtime dependency (hidapi in the fnox-core tree).
FROM ghcr.io/casualjim/bare:libcxx-udev-ssl
# eBPF capture needs root and BPF, PERFMON, and NET_ADMIN capabilities.
# hadolint ignore=DL3002,DL3066
USER root
ARG BIN_DIR=.
COPY ${BIN_DIR}/arkham /usr/local/bin/arkham
ENTRYPOINT ["arkham"]
CMD ["serve"]