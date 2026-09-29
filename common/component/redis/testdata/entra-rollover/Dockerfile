FROM golang:1.24.13

WORKDIR /workspace
COPY . .

RUN go test -c -o /usr/local/bin/redis-entra-repro ./common/component/redis

ENTRYPOINT ["/usr/local/bin/redis-entra-repro", "-test.v", "-test.timeout=7m", "-test.run=^TestEntraIDPoolRolloverRepro$", "-test.count=1"]
