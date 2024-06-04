wget https://github.com/libbpf/libbpf/archive/refs/tags/v1.4.0.tar.gz && \
    tar xvf v1.4.0.tar.gz && \
    cd libbpf-1.4.0/src && \
    make -j`nproc` && \
    make install install_uapi_headers
