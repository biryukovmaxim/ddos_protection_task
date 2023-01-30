FROM golang:1.19-alpine as builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN go build -o /app/client ./cmd/client

FROM alpine as runner
COPY --from=builder /app/client /app/client
CMD ["/app/client"]
#CMD ["sleep","3600"]

