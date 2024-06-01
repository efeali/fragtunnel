# Fragtunnel
Fragtunnel is a PoC TCP tunneling tool that exploits the design flaw that IDS/IPS engines and Next Generation Firewalls have; therefore, it can tunnel your application's traffic to the target server and back while not being detected and blocked by Next Generation firewalls using Layer 7 application rules.

### The issue
IDS/IPS engines used by the most next-generation firewalls allow a few packets of data to reach the destination while they collect enough information to make a verdict on whether they should allow or block the traffic. This is a design flaw that was discussed and published by different researchers within the last decade and can be exploited by malicious actors (if they were not already??). A few years ago, a few interesting findings made me curious about this funny behavior, and I did my research and wrote a simple PoC code without being aware of other researchers work. That PoC code was good to just demonstrate the bypass, but it wasn't really useful for other use cases. For a long time, I was envisioning developing a tunneling tool that you can just use with any tool you have and bypass NGFWs without changing their source code. Finally, meet fragtunnel! It may not be perfect yet, but it does the job ;)

## How it works?
- Data received from your local application (tunnel client side) or from target server (tunnel server side)
- received data gets encoded/decoded (optional)
- then sliced into smaller fragments.
- each fragment gets sent one by one over the tunnel, each fragment within a new TCP session
- fragments coming out from tunnel gets merged to make original data
- finally, restored original data gets sent to its target (either to your application at local or to the target server)

## Usage
### Set up a tunnel server:
```
python fragtunnel.py -b <interface-ip>:<port-to-listen>
```
Straightforward. This will be your tunnel server listening for a tunnel client connection. Once the tunnel client is connected, it will pass target information to the server first, and then the server will establish a connection to the final target.

### Set up a tunnel client
```
python fragtunnel.py -p <local-port-to-listen> -t <target-server-address>:<target-server-port> -T <tunnel-server-address>:<tunnel-server-port>
```
Example:
```
python fragtunnel.py -p 1234 -t mywebsite.com:80 -T 1.2.3.4:80
```

Once executed, the tunnel client will setup a local server on the local port (-p) so you can connect with your application.
Then the tunnel client will connect to the target tunnel server using the address and port number provided (-T) and will send target details provided (-t) to the tunnel server so the tunnel server can establish a connection to the final target on its side.

## To-do
This is the initial version of the tool, and currently it has some shortcomings, like:
- Tunnel traffic is not multithreaded; therefore, the overall speed is slow. Depending on the tool you use and its timeout value, there is quite a bit of a chance that your tool may timeout while sending or receiving the data.
- Currently, it does not support SSL/TLS. That's something planned to be added.
- The tool was tested with a limited number of applications. There might be bugs of which I am not aware yet, but again, this is a working PoC I wanted to share with the community.

## Final note:
This is for research and educational purposes only! Do not use this tool for any unauthorized activities or bad things.


