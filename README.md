# nginx-quic-lb
This is a deployable implementation of the load balancer side of the QUIC-LB protocol built on NGINX UDP Proxy. This is not to be confused with the QUIC-LB reference algorithm implementation at https://github.com/f5networks/quic-lb. It uses that library to actually encode and decode CIDs. This project wraps the encode/decode with the necessary configuration and management in NGINX.

See https://quicwg.org/load-balancers/draft-ietf-quic-load-balancers.html for the specification that defines this implementation.

# Installation instructions

```
sudo apt install gcc make libssl-dev
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

This example specifies support for three different configurations, each assigned to a config rotation codepoint. Each of these configurations, in this example, uses a different algorithm. In general, you would only need one quic-lb line in a production load balancer and would only add a second line when rotating keys in your server pool (see section 3.1 of the spec for more on this).

For dynamic SID allocation, simply add a parameter 'lb-timeout' to one or more
of the quic-lb lines, with a value (in seconds) greater than zero and responding
to how long a SID allocation can be unused before returning to the pool. For a
cr that is dynamically allocated, you need not assign an SID. For example, if
cr=1 has a nonzero lb-timeout value, there is no need to attach an sid1
parameter to any pool member.

Then type

```
sudo nginx
```

to start the server.

## Retry Services

In the "upstream server_pool" block, you can add this line:

```
        quic-lb retry-service key=1234567890abcdef1234567890abcdef iv=1234567890abcdef;
```

This instantiates a non-shared-state Retry Service that always sends Retry in
response to an Initial unless that Initial contains a valid token. It always
admits QUIC versions other than 1. If admitted, the packet will pass to the
load balancing logic to route. There MUST be at least one QUIC-LB load
balancing configuration in the block as well.

The key and iv are for internal use, so that the service can authenticate its
own tokens, and need not be shared with other entities. The key is always
16 bytes and the iv is always 8 bytes.

## Notes
[1] See https://nginx.org/en/docs/configure.html for configure flags. One string that has the necessary flags is

```
--prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib/nginx/modules --conf-path=/etc/nginx/nginx.conf
--error-log-path=/var/log/nginx/error.log --pid-path=/var/run/nginx.pid --lock-path=/var/run/nginx.lock --user=nginx
--group=nginx --build=Ubuntu --builddir=builds --with-stream --with-openssl=/usr/bin --without-http_rewrite_module
--without-http_gzip_module
```
There is probably a smaller minimum set, but this one works for sure in Ubuntu

[2] There can be up to three quic-lb commands, each corresponding to a different algorithm & settings the load balancer is executing. Possible parameters:
* "cr": Config Rotation (Integer from 0 to 2 inclusive). The load balancer will apply the configuration in that line to any compliant Connection ID whose first two bits matches this parameter.
* "sidl": Server ID length (Positive integer, limits depend on the algorithm). If cr and sidl are the only parameters, that implies that this config uses the "Plaintext CID algorithm"
* "key": Encryption key (16 byte opaque, hexidecimal). This encoding must be a 32-character hexidecimal representation of the key. The presence of this parameter implies the use of the Stream Cipher or Block Cipher CID algorithm.
* "nonce_len": Nonce Length (Positive Integer > 7). The presence of this parameter implies use of the Stream Cipher CID algorithm.

[3] Each server can be assigned between 1 and 3 Server IDs (sid0, sid1, sid2). The integer index indicates the config which uses this assignment. This is a hexidecimal representation of the opaque field. There must be exactly twice as many characters as the sidl of the associated configuration.

# Testing

A very quick test is to fill in fields in the nginx.conf file above as follows:

```
server localhost:4434 sid0=41414141;
server localhost:4435 sid0=42424242;
...
listen 443 udp;
```

As you're not listening on 4434 or 4435, it will help to disable the ICMP destination unreachable so that NGINX doesn't give up on the server:
```
sudo iptables -I OUTPUT -p icmp --icmp-type destination-unreachable -j DROP
```

Then you can type

```
tcpdump -i lo udp
nc -u localhost 443
00AAAAfoo
^c
nc -u localhost 443
00BBBBfoo
```

If everything is working correctly, cr=0 is the Plaintext CID algorithm with a 4-byte server ID. The two "servers" have server IDs easily expressible in ASCII.

Netcat will send a 10-byte UDP payload that is long enough for the proxy to extract the server ID. The tcpdump should show a UDP packet arrive on port 443 and be routed to 4434.
Closing netcat is necessary to set a new port so that later datagrams are sent to the same server.
Then a second call with SID BBBB will be routed to 4435.

Other SIDs will be routed using NGINX's Round Robin algorithm, as there is no server mapping.

Netcat is impractical for testing Retry Services due to the variable packet
contents and the short token expiration time. It is best tested with a full
QUIC client implementation.
