FROM --platform=linux/amd64 golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o main .

FROM --platform=linux/amd64 gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /app/main /main
COPY --from=builder /app/public /public

USER nonroot:nonroot
WORKDIR /

ENV PORT=8080
EXPOSE 8080

CMD ["/main"]
