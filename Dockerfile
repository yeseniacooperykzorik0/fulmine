# first image used to build the sources
FROM golang:1.21 AS builder

ARG VERSION
ARG COMMIT
ARG DATE
ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY . .

RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags="-X 'main.Version=${COMMIT}' -X 'main.Commit=${COMMIT}' -X 'main.Date=${COMMIT}'" -o bin/ark-wallet cmd/ark-wallet/main.go

# Second image, running the ark-wallet executable
FROM debian:buster-slim

# $USER name, and data $DIR to be used in the 'final' image
ARG USER=ArkLabsHQ
ARG DIR=/home/ArkLabsHQ

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

COPY --from=builder /app/bin/* /usr/local/bin/

# NOTE: Default GID == UID == 1000
RUN adduser --disabled-password \
						--home "$DIR/" \
						--gecos "" \
						"$USER"
USER $USER

# Prevents 'VOLUME $DIR/.ark-wallet/' being created as owned by 'root'
RUN mkdir -p "$DIR/.ark-wallet/"

# Expose volume containing all 'ark-wallet' data
VOLUME $DIR/.ark-wallet/

ENTRYPOINT [ "ark-wallet" ]
    