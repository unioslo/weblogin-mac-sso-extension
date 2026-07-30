# Build micromdm/scep locally so the mock MDM has no external image dependency.
# (Upstream publishes no public image; prod mirrors one into GCP AR, which is GCP-only.)
# Clone-and-build in-module — `go install .../v2/...@tag` trips scep's module-path quirk.
FROM golang:1.23-alpine AS build
ARG SCEP_VERSION=v2.3.0
RUN apk add --no-cache git
RUN git clone --depth 1 --branch "${SCEP_VERSION}" https://github.com/micromdm/scep /src
WORKDIR /src
RUN CGO_ENABLED=0 go build -o /scepserver ./cmd/scepserver

FROM alpine:3.20
COPY --from=build /scepserver /usr/local/bin/scepserver
ENTRYPOINT ["scepserver"]
