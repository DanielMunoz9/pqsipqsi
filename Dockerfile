FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
RUN adduser -D -u 1000 user
USER user
WORKDIR /home/user/app
COPY --from=builder --chown=user /app/main .
COPY --from=builder --chown=user /app/public ./public
ENV PORT=7860
EXPOSE 7860
CMD ["./main"]