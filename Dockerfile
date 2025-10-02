FROM golang:1.22.0-alpine3.19 AS builder

RUN apk --update add ca-certificates
WORKDIR $GOPATH/src/janic0/cert-alert/
COPY . .
RUN go get -v
RUN go build -o /go/bin/cert-alert

FROM scratch
WORKDIR /app
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /go/bin/cert-alert /go/bin/cert-alert
ENTRYPOINT ["/go/bin/cert-alert"]
