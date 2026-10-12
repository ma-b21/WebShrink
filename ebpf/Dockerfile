FROM docker.1panel.live/library/alpine:3.20

# Install toolchain pieces required for compiling eBPF objects (clang/llvm) and
# the C++ loader (musl g++, libbpf, libelf, zlib). bpftool is handy for inspection.
RUN apk add --no-cache \
        bash \
        build-base \
        clang \
        llvm \
        llvm-dev \
        libbpf \
        libbpf-dev \
        elfutils-dev \
        zlib-dev \
        linux-headers \
        bpftool \
        pkgconf \
        python3 \
        py3-pip \
        git \
        ca-certificates

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /workspace
COPY . /workspace

CMD ["/bin/sh"]
