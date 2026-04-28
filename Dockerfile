FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o main .

FROM alpine:latest
RUN apk --no-cache add ca-certificates wget tar libstdc++ libgcc

# Download Piper TTS Linux binary
RUN mkdir -p /opt/piper && \
    wget -q -O /tmp/piper.tar.gz \
      "https://github.com/rhasspy/piper/releases/download/2023.11.14-2/piper_linux_x86_64.tar.gz" && \
    tar -xzf /tmp/piper.tar.gz -C /opt/piper && \
    rm /tmp/piper.tar.gz && \
    chmod +x /opt/piper/piper/piper

# Download voices
RUN mkdir -p /opt/piper-voices && \
    wget -q -O /opt/piper-voices/es_MX-claude-high.onnx \
      "https://huggingface.co/rhasspy/piper-voices/resolve/main/es/es_MX/claude/high/es_MX-claude-high.onnx" && \
    wget -q -O /opt/piper-voices/es_MX-claude-high.onnx.json \
      "https://huggingface.co/rhasspy/piper-voices/resolve/main/es/es_MX/claude/high/es_MX-claude-high.onnx.json"

RUN adduser -D -u 1000 user
USER user
WORKDIR /home/user/app
COPY --from=builder --chown=user /app/main .
COPY --from=builder --chown=user /app/public ./public

# Put piper where main.go expects it: tts/piper/piper/piper
RUN mkdir -p tts/piper/piper tts/voices && \
    cp /opt/piper/piper/piper tts/piper/piper/piper && \
    cp /opt/piper-voices/es_MX-claude-high.onnx tts/voices/ && \
    cp /opt/piper-voices/es_MX-claude-high.onnx.json tts/voices/

ENV PORT=7860
EXPOSE 7860
CMD ["./main"]