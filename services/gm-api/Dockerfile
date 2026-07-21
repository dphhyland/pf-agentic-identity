# Grant Management API extension service.
#
# This is the real GM API: it fronts PingFederate's Persistent Grant Management
# API and adds the /grants/{id}/evaluate endpoint. It needs a reachable
# PingFederate and an AuthZEN PDP -- see .env.example for what to set.
FROM golang:1.23-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /out/gm-api ./cmd/gm-api

FROM alpine:3.20
RUN apk --no-cache add ca-certificates
WORKDIR /app

COPY --from=build /out/gm-api /app/gm-api

EXPOSE 8080
CMD ["/app/gm-api"]
