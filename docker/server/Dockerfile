FROM golang:1.19 as builder
RUN apt-get update && apt-get install -y build-essential linux-headers-generic libc-dev libbsd-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . ./
RUN go build -o server ./cmd/server

FROM ubuntu:20.04 as runner
RUN apt-get update && apt-get install -y build-essential linux-headers-generic libc-dev libbsd-dev sudo
COPY --from=builder /app/server /app/server
EXPOSE 5051
EXPOSE 1053
#CMD ["sleep","3600"]
CMD ["app/server"]
