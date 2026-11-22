FROM node:24-alpine AS web
WORKDIR /build
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ .
RUN npm run build

FROM rust:1.98-alpine@sha256:7cc1c22d77d9432f7fe012a70e6d3e555af54c2a6832700ed7d553f1769ae89f AS backend
RUN apk add --no-cache build-base
WORKDIR /build
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/migrations ./migrations
COPY backend/.sqlx ./.sqlx
ENV SQLX_OFFLINE=true
ARG CERTHIA_CARGO_FEATURES=""
COPY backend/benches ./benches
COPY backend/src ./src
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --release --locked --features "$CERTHIA_CARGO_FEATURES" && cp target/release/digestdesk /build/digestdesk

FROM ghcr.io/aquasecurity/trivy:0.76.2@sha256:8f6bb947dbc528902e11f2f5be52f7b519f6a39d5d148f41166f2040499768fb AS trivy

FROM alpine:3.24 AS runtime
LABEL org.opencontainers.image.title="Certhia"
RUN apk add --no-cache ca-certificates skopeo \
    && addgroup -S -g 10001 certhia \
    && adduser -S -D -H -u 10001 -G certhia certhia \
    && mkdir -p /data/tmp \
    && chown -R certhia:certhia /data \
    && chmod 700 /data /data/tmp
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
COPY --from=backend /build/digestdesk /usr/local/bin/digestdesk
COPY --from=web /build/build /app/web
ENV CERTHIA_BIND=0.0.0.0:8080 CERTHIA_DATA_DIR=/data CERTHIA_WEB_DIR=/app/web HOME=/data TMPDIR=/data/tmp
USER certhia
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=5s \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/api/ready || exit 1
ENTRYPOINT ["/usr/local/bin/digestdesk"]

FROM moby/buildkit:v0.28.0@sha256:37539dd4d60fc70968d164d3850d903a2c56f6402214a1953fbf9fcb81ada731 AS buildkit

FROM runtime AS production

FROM production AS integrations
USER root
RUN apk add --no-cache kubectl
COPY --from=buildkit /usr/bin/buildctl /usr/local/bin/buildctl
USER certhia

FROM --platform=$BUILDPLATFORM alpine:3.24 AS scanner-downloads
ARG TARGETARCH
RUN apk add --no-cache curl
WORKDIR /downloads
# Checksums come from the upstream release checksum files for each architecture.
RUN set -eux; \
    mkdir /scanners; \
    fetch() { \
        curl --fail --silent --show-error --location --retry 3 "$1/$2" -o "$2"; \
        printf '%s  %s\n' "$3" "$2" | sha256sum -c -; \
        case "$2" in \
            *.tar.gz) tar -xzf "$2" -C /scanners "$4" ;; \
            *) mv "$2" "/scanners/$4" ;; \
        esac; \
        chmod 0755 "/scanners/$4"; \
    }; \
    case "$TARGETARCH" in \
        amd64) \
            fetch https://github.com/anchore/grype/releases/download/v0.122.1 \
                grype_0.122.1_linux_amd64.tar.gz f1ba7e2917ee1395618de20a98da0aa7c0fb1788927797651047c50502a37538 grype; \
            fetch https://github.com/anchore/syft/releases/download/v1.57.2 \
                syft_1.57.2_linux_amd64.tar.gz ad92bd3ec1b94a3df01d4d0aec199afa9c42b72e86da436ff5f837914d32706b syft; \
            fetch https://github.com/goodwithtech/dockle/releases/download/v0.4.15 \
                dockle_0.4.15_Linux-64bit.tar.gz 8bfc9183d1d3d67800edb45bea4bb63ddf1d28bec5f89944075a07007d79caad dockle; \
            fetch https://github.com/google/osv-scanner/releases/download/v2.7.1 \
                osv-scanner_linux_amd64 fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8 osv-scanner; \
            fetch https://github.com/wagoodman/dive/releases/download/v0.13.1 \
                dive_0.13.1_linux_amd64.tar.gz 0970549eb4a306f8825a84145a2534153badb4d7dcf3febd1967c706367c3d0e dive; \
            ;; \
        arm64) \
            fetch https://github.com/anchore/grype/releases/download/v0.122.1 \
                grype_0.122.1_linux_arm64.tar.gz 819e5be3d9516432fedb7b6b56df7306c3a16607606dfc05826eefbb00e471da grype; \
            fetch https://github.com/anchore/syft/releases/download/v1.57.2 \
                syft_1.57.2_linux_arm64.tar.gz 8efe605309c98798e1ee0cffdcf8c05ca26819b4cd44c0b03650f1e963e9bdb6 syft; \
            fetch https://github.com/goodwithtech/dockle/releases/download/v0.4.15 \
                dockle_0.4.15_Linux-ARM64.tar.gz 14c2fbcd675afaa0f1717e97ab71eee178dabdef676066189f49bad0f53b8762 dockle; \
            fetch https://github.com/google/osv-scanner/releases/download/v2.7.1 \
                osv-scanner_linux_arm64 983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81 osv-scanner; \
            fetch https://github.com/wagoodman/dive/releases/download/v0.13.1 \
                dive_0.13.1_linux_arm64.tar.gz 2fcd2cf20f634ccdb41efac44048b204bfc867c115641f37a7420693ed480a18 dive; \
            ;; \
        *) echo "Unsupported scanner architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac

FROM integrations AS scanners
COPY --from=scanner-downloads /scanners/ /usr/local/bin/

FROM production AS default
