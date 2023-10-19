FROM alpine:20230901
RUN apk update && apk add --upgrade libcrypto3 libssl3

RUN adduser -u 10000 -D -g '' vuloperator vuloperator

COPY vul-operator /usr/local/bin/vul-operator

USER 10000

ENTRYPOINT ["vul-operator"]
