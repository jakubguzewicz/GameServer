FROM ubuntu:latest
WORKDIR /app
RUN apt update
RUN apt install openssh-server g++ cmake git -y
RUN apt install -y pkg-config libsasl2-dev
COPY lib/libcrypto.so.3 .
COPY lib/libssl.so.3 . 
COPY lib/libprotobuf.so.23.0.4 .
RUN cd ~\
    && wget https://github.com/mongodb/mongo-cxx-driver/releases/download/r3.10.1/mongo-cxx-driver-r3.10.1.tar.gz \
    && tar -xzf mongo-cxx-driver-r3.10.1.tar.gz \
    && cd mongo-cxx-driver-r3.10.1/build \
    && cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local -DCMAKE_CXX_STANDARD=17 \
    && cmake --build . \
    && cmake --build . --target install \
    && cd ~ \
    && rm mongo-cxx-driver-r3.10.1.tar.gz \
    && rm -rf mongo-cxx-driver-r3.10.1

COPY auth_server/ .
ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"
ENTRYPOINT ["./auth_server"]