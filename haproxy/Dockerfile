FROM haproxy:2.4-dev
RUN apt-get update && apt-get install -y git openssl dialog apt-utils wget
RUN wget http://deb.debian.org/debian/pool/main/o/openssl1.0/libssl1.0.2_1.0.2u-1~deb9u1_amd64.deb
RUN dpkg -i libssl1.0.2_1.0.2u-1~deb9u1_amd64.deb
RUN wget http://deb.debian.org/debian/pool/main/o/openssl1.0/libssl1.0-dev_1.0.2u-1~deb9u1_amd64.deb
RUN dpkg -i libssl1.0-dev_1.0.2u-1~deb9u1_amd64.deb
RUN ldconfig
RUN apt-get install -y lua5.3-dev
RUN apt-get install -y lua5.3
RUN apt-get install -y luarocks
RUN luarocks install redis-lua
RUN luarocks install base64
RUN luarocks install rxi-json-lua
#RUN luarocks remove lua-cjson
#RUN luarocks install lua-cjson 2.1.0-1
RUN luarocks install jwt
