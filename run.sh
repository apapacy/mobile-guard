mkdir -p key

openssl genrsa -out key/private.pem 4096
openssl rsa -in key/private.pem -outform PEM -pubout -out key/public.pem
openssl req -out key/cert.csr -key key/private.pem -new -subj '/C=UA/ST=Ukraine/L=Kyiv/CN=test.ua'
openssl x509 -req -in key/cert.csr -signkey key/private.pem -out key/cert.pem -days 7

openssl genrsa -out key/private_tmp.pem 4096
openssl rsa -in key/private_tmp.pem -outform PEM -pubout -out key/public_tmp.pem
openssl req -out key/cert_tmp.csr -key key/private_tmp.pem -new -subj '/C=UA/ST=Ukraine/L=Kyiv/CN=test.ua'
openssl x509 -req -in key/cert_tmp.csr -signkey key/private_tmp.pem -out key/cert_tmp.pem -days 7

docker-compose up --build --force-recreate --abort-on-container-exit
