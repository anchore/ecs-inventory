FROM gcr.io/distroless/static-debian11:debug AS build

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /tmp

COPY anchore-ecs-inventory /

ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.source=$VCS_URL

LABEL org.opencontainers.image.title="ecg"
LABEL org.opencontainers.image.description="AEI (Anchore ECS Inventory) is a tool to gather an inventory of images in use by Amazon Elastic Container Service (ECS)."
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENTRYPOINT ["/anchore-ecs-inventory"]
