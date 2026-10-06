# syntax=docker/dockerfile:1.7.0@sha256:dbbd5e059e8a07ff7ea6233b213b36aa516b4c53c645f1817a4dd18b83cbea56
FROM alpine:3.21.3@sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c
ARG EXPECTED_SHA256
RUN --mount=type=secret,id=synthetic_token,required=true \
    test "$(sha256sum /run/secrets/synthetic_token | cut -d ' ' -f 1)" = "$EXPECTED_SHA256" && \
    printf 'secure synthetic build\n' > /build-result
RUN test ! -e /run/secrets/synthetic_token
