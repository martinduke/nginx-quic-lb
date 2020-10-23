# nginx-quic-lb
This is a deployable implementation of the load balancer side of the QUIC-LB protocol built on NGINX UDP Proxy. This is not to be confused with the QUIC-LB reference algorithm implementation at https://github.com/f5networks/quic-lb. It uses that library to actually encode and decode CIDs. This project wraps the encode/decode with the necessary configuration and management in NGINX.

See https://quicwg.org/load-balancers/draft-ietf-quic-load-balancers.html for the specification that defines this implementation.

# Installation instructions

```
git clone https://github.com/martinduke/nginx-quic-lb.git
cd nginx-quic-lb
./auto/configure <flags>
make
sudo make install
```

# Config instructions
Add something like this example to your nginx.conf file:

```
stream {
    upstream server_pool {
        quic-lb cr=0 sidl=4;
        quic-lb cr=1 sidl=6 key=abcdefabcdefabcdefabcdefabcdefab; 
        quic-lb cr=2 sidl=4 key=fedcbafedcbafedcbafedcbafedcbafe nonce_len=8;
        server <addr>:<port> sid0=01234567 sid1=89abcdef0123 sid2=456789ab;
        server <addr>:<port> sid0=23456789 sid1=abcdef012345 sid2=6789abcd;
    }
 
    server {
        listen <port> udp;
        proxy_pass server_pool;
    }
}
```

## Notes
[1] See https://nginx.org/en/docs/configure.html for configure flags. One string that has the necessary flags is

```
--prefix=/etc/nginx --sbin-path=/usr/xbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf
--error-log-path=/var/log/nginx/error.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --user=nginx
--group=nginx --build=Ubuntu --builddir=builds --with-stream --with-openssl=/usr/bin --without-http_rewrite_module
```
There is probably a smaller minimum set, but this one works in Ubuntu

[2] There can be up to three quic-lb commands, each corresponding to a different algorithm & settings the load balancer is executing. Possible parameters:
* "cr": Config Rotation (Integer from 0 to 2 inclusive). The load balancer will apply the configuration in that line to any compliant Connection ID whose first two bits matches this parameter.
* "sidl": Server ID length (Positive integer, limits depend on the algorithm). If cr and sidl are the only parameters, that implies that this config uses the "Plaintext CID algorithm"
* "key": Encryption key (16 byte opaque, hexidecimal). This encoding must be a 32-character hexidecimal representation of the key. The presence of this parameter implies the use of the Stream Cipher or Block Cipher CID algorithm.
* "nonce_len": Nonce Length (Positive Integer > 7). The presence of this parameter implies use of the Stream Cipher CID algorithm.

[3] Each server can be assigned between 1 and 3 Server IDs (sid0, sid1, sid2). The integer index indicates the config which uses this assignment. This is a hexidecimal representation of the opaque field. There must be exactly twice as many characters as the sidl of the associated configuration.

