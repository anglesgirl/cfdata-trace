FROM golang:1.26.2-alpine AS build

WORKDIR /src
COPY combined_refactor/go.mod combined_refactor/go.sum ./
RUN go mod download
COPY combined_refactor/ ./
RUN mkdir -p /out && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cfdata-trace .

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/cfdata-trace /cfdata-trace
ENV CFDATA_TRACE_ONLY=1
EXPOSE 13335
USER nonroot:nonroot
ENTRYPOINT ["/cfdata-trace"]
CMD ["-port", "13335", "-host", "0.0.0.0", "-skipgeo"]
