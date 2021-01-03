FROM golang:1.15-alpine AS builder
RUN set -ex \
    && apk add --no-cache  git

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN ./ci/build

FROM alpine:3.12
EXPOSE 8080

WORKDIR /app

COPY --from=builder /app/dist/2fa /app/2fa

CMD ["./2fa"]
