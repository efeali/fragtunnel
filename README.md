Fragtunnel is a PoC TCP tunnel tool which exploits the design flaw an IDS/IPS engines and Next Generation Firewalls have.


## Usage
### Set up a tunnel server:
```
python fragtunnel.py -b <interface-ip>:<port-to-listen>
```
Straightforward. This will be your tunnel server listening for tunnel client connection. Once the tunnel client is connected it will pass target information to the server first, then the server will establish a connection to the final target.

### Set up a tunnel client
```
python fragtunnel.py -p <local-port-to-listen> -t <target-server-address>:<target-server-port> -T <tunnel-server-address>:<tunnel-server-port>
```
Ex.
```
python fragtunnel.py -p 1234 -t mywebsite.com:80 -T 1.2.3.4:80
```

Once executed, the tunnel client will setup a local server on local port (-p) so you can connect with your application.
Then the tunnel client will connect to target tunnel server using the address and port number provided (-T), and will send target details provided (-t) to the tunnel server so the tunnel server can establish a connection to the final target on its side.


