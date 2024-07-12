FROM ubuntu:latest
WORKDIR /app
RUN apt update
RUN apt install g++ -y
COPY lib/libcrypto.so.3* .
COPY lib/libssl.so.3* . 
COPY lib/libprotobuf.so.23* .
COPY broker/ .
ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:./"
EXPOSE 4720/udp
ENTRYPOINT ["./broker"]