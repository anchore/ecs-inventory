FROM gcr.io/distroless/static-debian13:debug@sha256:11c839f18a0d7b91b093cda53a5d4cee84f23ec450a6f6e1bf17ab12bf296333 AS build

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /tmp

COPY anchore-ecs-inventory /
COPY docker-compose/anchore-ecs-inventory.yaml /etc/xdg/anchore-ecs-inventory/config.yaml

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.source=$VCS_URL

LABEL org.opencontainers.image.title="anchore-ecs-inventory"
LABEL org.opencontainers.image.description="AEI (Anchore ECS Inventory) is a tool to gather an inventory of images in use by Amazon Elastic Container Service (ECS)."
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.licenses="Apache-2.0"

USER 1000
HEALTHCHECK CMD ["/anchore-ecs-inventory", "version"]

ENTRYPOINT ["/anchore-ecs-inventory"]
