FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates

RUN adduser -D -u 1000 user
USER user
WORKDIR /home/user/app

COPY --from=builder --chown=user /app/main ./main
COPY --from=builder --chown=user /app/public ./public

ENV PORT=8080
EXPOSE 8080

CMD ["./main"]
