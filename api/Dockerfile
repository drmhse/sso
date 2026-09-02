# Packages a binary that cargo-zigbuild already cross-compiled on the host; it
# builds nothing itself.
#
#   docker buildx build -f Dockerfile --platform linux/amd64,linux/arm64 \
#     --build-arg BINARY_NAME=sso_sqlite .

FROM alpine:3.20

LABEL org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/drmhse/AuthOS"

ARG TARGETARCH
ARG BINARY_NAME=sso_sqlite

# No apk install: the binaries are statically linked musl, so they need no
# runtime library, and the base already ships ca-certificates-bundle for the
# trust store. addgroup/adduser/install are busybox builtins.
RUN addgroup -S -g 10001 authos \
    && adduser -S -D -H -u 10001 -G authos authos \
    && install -d -m 0700 -o authos -g authos /app /app/data /app/geoip

WORKDIR /app

# Set the mode here rather than in a later RUN chmod. Changing a file's mode
# rewrites the whole file into a new layer, which stored this 17 MiB binary
# twice and doubled the image.
COPY --chown=authos:authos --chmod=0555 \
    target/dist/linux-${TARGETARCH}/${BINARY_NAME} /app/sso
COPY --chown=authos:authos --chmod=0555 docker-entrypoint.sh /app/docker-entrypoint.sh

# The AGPL requires the notice to travel with the conveyed binary.
COPY --chown=root:root LICENSE /usr/share/licenses/authos/AGPL-3.0.txt

USER 10001:10001

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${SERVER_PORT:-3000}/health/ready" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
