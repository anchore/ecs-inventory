FROM golang:latest as build
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /app/output/ecg

FROM gcr.io/distroless/static:nonroot
USER nonroot:nobody
ARG BUILD_DATE
ARG BUILD_VERSION
ARG VCS_REF
ARG VCS_URL

LABEL org.opencontainers.image.created=$BUILD_DATE
LABEL org.opencontainers.image.version=$BUILD_VERSION
LABEL org.opencontainers.image.revision=$VCS_REF
LABEL org.opencontainers.image.source=$VCS_URL

LABEL org.opencontainers.image.title="ecg"
LABEL org.opencontainers.image.description="ECG (Elastic Container Gatherer) is a tool to gather an inventory of images in use by Amazon Elastic Container Service (ECS)."
LABEL org.opencontainers.image.vendor="Anchore, Inc."
LABEL org.opencontainers.image.licenses="Apache-2.0"

COPY --from=build /app/output/ecg /usr/bin/ecg
ENTRYPOINT ["ecg"]