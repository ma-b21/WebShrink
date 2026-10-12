FROM docker.1panel.live/library/alpine:3.22

RUN apk add --no-cache ca-certificates

ENV GOLANG_VERSION=1.26-devel_969366f3f6

# don't auto-upgrade the gotoolchain
# https://github.com/docker-library/golang/issues/472
ENV GOTOOLCHAIN=local

ENV GOPATH=/go
ENV GOROOT=/usr/local/go
ENV PATH=$GOPATH/bin:/usr/local/go/bin:$PATH

COPY . /usr/local/go
RUN mkdir /go
RUN chmod -R 1777 "$GOPATH"
WORKDIR $GOPATH