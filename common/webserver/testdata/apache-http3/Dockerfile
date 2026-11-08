# Test reference only. Run with --network none and join its loopback namespace
# from the comparison test; never publish this experimental server.
FROM httpd@sha256:a30cd4cd57f3f3c3be9b2d16384d2488839996bb14c67df2b51f1ecbb3e584a1 AS dependencies
RUN sed -i 's|http://deb.debian.org|https://deb.debian.org|g' /etc/apt/sources.list.d/debian.sources \
    && apt-get update -o Acquire::Retries=1 -o Acquire::https::Timeout=30 \
    && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config \
    libssl-dev=3.5.7-1~deb13u3 libapr1-dev=1.7.5-1 \
    libaprutil1-dev=1.6.3-3+deb13u1 libpcre2-dev libnghttp2-dev zlib1g-dev \
    && dpkg-query -W > /reference-packages.txt

FROM dependencies AS build
# Download the two archives listed in sources.sha256 into this build context.
COPY naive-httpd.tar.gz naive-nghttp3.tar.gz /sources/
COPY sources.sha256 /sources/sources.sha256
RUN cd /sources && sha256sum -c sources.sha256 \
    && mkdir -p /build/httpd /build/nghttp3 \
    && tar xzf naive-httpd.tar.gz -C /build/httpd --strip-components=1 \
    && tar xzf naive-nghttp3.tar.gz -C /build/nghttp3 --strip-components=1
RUN cd /build/nghttp3 && autoreconf -fi \
    && ./configure --prefix=/opt/h3 --enable-lib-only \
    && make -j2 && make install
ENV LD_LIBRARY_PATH=/opt/h3/lib
ENV PKG_CONFIG_PATH=/opt/h3/lib/pkgconfig
RUN cd /build/httpd && ./buildconf \
    && ./configure --prefix=/opt/httpd --enable-mods-shared=most \
       --with-mpm=event --enable-http2 --enable-http3 --enable-ssl --with-nghttp3=/opt/h3 \
    && make -j2 && make install
COPY httpd.conf /opt/httpd/conf/httpd.conf
COPY index.html /opt/httpd/htdocs/index.html
COPY start.sh /reference-start.sh
ENTRYPOINT ["sh", "/reference-start.sh"]
