# openssl报错
echo "/usr/local/openssl/lib" >> /etc/ld.so.conf.d/libc.conf && ldconfig

# 获取CA证书
/usr/local/openssl/bin/openssl genpkey -algorithm RSA -out ca.key

/usr/local/openssl/bin/openssl req -new -x509 -key ca.key -out ca.crt

# 为客户端颁发证书
### 生成私钥
/usr/local/openssl/bin/openssl genpkey -algorithm RSA -out client.key
### 创建客户端证书签署请求
/usr/local/openssl/bin/openssl req -new -key client.key -out client.csr
### 使用自签名CA证书对客户端CSR进行签名，生成客户端证书
/usr/local/openssl/bin/openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt

# 为服务器颁发证书
### 生成私钥
/usr/local/openssl/bin/openssl genpkey -algorithm RSA -out server.key
### 创建服务器证书签署请求
/usr/local/openssl/bin/openssl req -new -key server.key -out server.csr
### 使用自签名CA证书对服务器CSR进行签名，生成服务器证书
/usr/local/openssl/bin/openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# 启动服务器
/usr/local/openssl/bin/openssl s_server -cert server.crt -key server.key -Verify 1 -CAfile ca.crt -keylogfile key.log

# 启动客户端
/usr/local/openssl/bin/openssl s_client -cert client.crt -key client.key -connect localhost:4433 -tls1_3


