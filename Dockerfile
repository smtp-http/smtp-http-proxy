FROM alpine:3.4

RUN apk --no-cache add g++ scons curl-dev boost-dev bash

ADD . /opt/src
RUN cd /opt/src && scons && scons check=1
RUN strip /opt/src/smtp-http-proxy
RUN cd /opt/src

CMD ["./smtp-http-proxy --bind 0.0.0.0 --port 25 --url http://ksat.luxshare-ict.com:9812/rpcapi/v1/ksat/core.mail/Send &"]
