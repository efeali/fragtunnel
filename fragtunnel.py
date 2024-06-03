import getopt
import queue
import socket
import threading
import time
import sys
import traceback

BUFFER_SIZE = 8192
FRAGMENT_SIZE = 1024

SECRET_KEY = b""
ENCRYPTED_TUNNEL = False
VERBOSE = False

TARGET_SET = False
TUNNEL_SERVER_IN_BUFFER = queue.Queue()
TUNNEL_SERVER_OUT_BUFFER = queue.Queue()
TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT, TARGET_IP, TARGET_PORT = str(""), int(0), str(""), int(0)
LOCAL_PORT, BIND_IP = int(0), str("")
CLIENT_TO_TARGET_SOCK = socket.socket


class FragmentManager:
    def __init__(self):
        self.data = b''
        self.fragmented_data = []
        self.total_data_size = 0
        self.fragmented_data_count = 0
        self.fragmented_data_index = 0

    # create fragments from given data and store them in a list
    def fragment_data(self, data):
        if ENCRYPTED_TUNNEL is True:
            self.data = encrypt_data(data)
        else:
            self.data = data
        self.total_data_size = len(self.data)
        self.fragmented_data_count = int(self.total_data_size / FRAGMENT_SIZE) + (
                self.total_data_size % FRAGMENT_SIZE > 0)

        for i in range(self.fragmented_data_count):
            self.fragmented_data.append(self.data[i * FRAGMENT_SIZE:(i + 1) * FRAGMENT_SIZE])

    # append a fragment to the list
    def append_fragment(self, fragment):
        self.fragmented_data.append(fragment)

    # get the next fragment from the list
    def get_next_fragment(self):
        if self.fragmented_data_index < self.fragmented_data_count:
            self.fragmented_data_index += 1
            return self.fragmented_data[self.fragmented_data_index - 1]
        else:
            return None

    # get initial count of fragments we have (not updated)
    def get_fragment_count(self):
        return self.fragmented_data_count

    # get the current count of fragments we have
    def get_current_fragment_count(self):
        return len(self.fragmented_data)

    # get the fragment and remove (FIFO)
    def get_fragment_and_remove(self):
        return self.fragmented_data.pop(0)

    # get the list of fragments
    def get_fragmented_data(self):
        return self.fragmented_data

    def get_total_data_size(self):
        return self.total_data_size

    # join all fragments, decode/decrypt and return the data
    def get_data(self):
        if ENCRYPTED_TUNNEL is True:
            return decrypt_data(b''.join(self.fragmented_data))
        else:
            return b''.join(self.fragmented_data)

    def clear(self):
        time.sleep(0.1)
        self.data = b''
        self.fragmented_data = []
        self.total_data_size = 0
        self.fragmented_data_count = 0
        self.fragmented_data_index = 0


class FragTunnel:
    SPECIAL_EOD = str("###>EOD<###")
    SPECIAL_ACK = str("###>ACK<###")
    SPECIAL_ERR = str("###>ERR<###")
    DATA = str("DATA")
    TARGET_STRING = str("####>TARGETIP:PORT<####")

    # send special ACK to tunnel connection
    @staticmethod
    def send_ack(s):
        if ENCRYPTED_TUNNEL is True:
            # send xor'ed special ACK to tunnel
            s.sendall(encrypt_data(FragTunnel.SPECIAL_ACK.encode()))
        else:
            s.sendall(FragTunnel.SPECIAL_ACK.encode())

    # send special EOD to tunnel connection
    @staticmethod
    def send_eod(s):
        if ENCRYPTED_TUNNEL is True:
            # send xor'ed special EOD to tunnel
            s.sendall(encrypt_data(FragTunnel.SPECIAL_EOD.encode()))
        else:
            s.sendall(FragTunnel.SPECIAL_EOD.encode())

    # send special ERR to tunnel connection
    @staticmethod
    def send_err(s):
        if ENCRYPTED_TUNNEL is True:
            # send xor'ed special ERR to tunnel
            s.sendall(encrypt_data(FragTunnel.SPECIAL_ERR.encode()))
        else:
            s.sendall(FragTunnel.SPECIAL_ERR.encode())

    # send a special message to set the target containing target ip and port
    @staticmethod
    def send_target_set_msg(s, target_ip, target_port):
        set_target_text = FragTunnel.TARGET_STRING + target_ip + ":" + str(target_port)
        if ENCRYPTED_TUNNEL is True:
            result = s.sendall(encrypt_data(set_target_text.encode()))
        else:
            result = s.sendall(set_target_text.encode())
        return result

    # receive data from tunnel connection, decrypt if needed and return the status and raw data
    @staticmethod
    def recv_data(s):
        data_obj = {"status": None, "raw_data": None}

        data = s.recv(FRAGMENT_SIZE)
        if not data:
            return data_obj
        else:
            if ENCRYPTED_TUNNEL is True:
                # xor data, get original content
                decrypted_data = decrypt_data(data)
            else:
                decrypted_data = data
            try:
                if decrypted_data.decode() == FragTunnel.SPECIAL_EOD:
                    data_obj["status"] = FragTunnel.SPECIAL_EOD
                elif decrypted_data.decode() == FragTunnel.SPECIAL_ACK:
                    data_obj["status"] = FragTunnel.SPECIAL_ACK
                elif decrypted_data.decode() == FragTunnel.SPECIAL_ERR:
                    data_obj["status"] = FragTunnel.SPECIAL_ERR
                elif decrypted_data.decode()[:23] == FragTunnel.TARGET_STRING:
                    data_obj["status"] = FragTunnel.TARGET_STRING
                    data_obj["raw_data"] = decrypted_data
                else:
                    data_obj["status"] = FragTunnel.DATA
                    data_obj["raw_data"] = data
            except UnicodeDecodeError:
                data_obj["status"] = FragTunnel.DATA
                data_obj["raw_data"] = data

            return data_obj

    # join all fragments in the buffer, decrypt it if needed and return the data
    @staticmethod
    def join_fragments(fragments_buffer):
        joined_data_list = []
        while not fragments_buffer.empty():
            joined_data_list.append(fragments_buffer.get())
        joined_data = b''.join(joined_data_list)
        if ENCRYPTED_TUNNEL is True:
            # xor all joined data, get original and send to target
            joined_data = decrypt_data(joined_data)
        return joined_data


# a wrapper encrypt function to easily switch between xor and other encryption in the future
def encrypt_data(data):
    return xor_data(data, SECRET_KEY)


# a wrapper decrypt function to easily switch between xor and other encryption in the future
def decrypt_data(data):
    return xor_data(data, SECRET_KEY)


# xor byte data with a key
def xor_data(original, key):
    # Convert key to bytes if it's a string
    key = key.encode() if isinstance(key, str) else key
    # Extend the key to original string's length
    extended_key = key * (len(original) // len(key)) + key[:len(original) % len(key)]
    # XOR each byte of the original string with the corresponding byte in the extended key
    xor_result = bytes(b1 ^ b2 for b1, b2 in zip(original, extended_key))
    return xor_result


# a function to check if the socket is connected
def is_connected(sock):
    try:
        sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        return True
    except socket.error:
        return False


# a function to print log messages if verbose mode is enabled
def log(message):
    if VERBOSE:
        print(message)


# a burnout, one time use, socket to send data, receive response, close and return a new socket
def burnout_socket_sender(tunnel_client_socket, data, eod=False):
    tunnel_client_socket.setblocking(1)
    if eod is True:
        FragTunnel.send_eod(tunnel_client_socket)
        log("Sent EOD")
    else:
        tunnel_client_socket.sendall(data)
        log("Sent data size: %d" % len(data))

    response = FragTunnel.recv_data(tunnel_client_socket)

    tunnel_client_socket.close()
    tunnel_client_socket = None  # clear the socket
    tunnel_client_socket = tunnel_client()

    return tunnel_client_socket


# a function to create fragments to be sent, send them one by one, finally send EOD and return a new socket
def tunnel_client_fragmented_data_sender(tunnel_client_socket, data):
    outgoing_fd_manager = FragmentManager()

    # fragment data
    outgoing_fd_manager.fragment_data(data)

    # fragment by fragment send encrypted data leveraging burnout_socket_sender
    for i in range(outgoing_fd_manager.get_fragment_count()):
        log("Sending fragment %d" % i)
        tunnel_client_socket = burnout_socket_sender(tunnel_client_socket, outgoing_fd_manager.get_next_fragment())

    # finally send EOD
    tunnel_client_socket = burnout_socket_sender(tunnel_client_socket, "", True)

    outgoing_fd_manager.clear()
    return tunnel_client_socket


# a handler for local server and tunnel client couple
def handle_local_client(local_connection, tunnel_client_socket):
    try:
        local_connection.setblocking(0)
        tunnel_client_socket.setblocking(0)

        # create a list of fragmented data
        incoming_fd_manager = FragmentManager()

        while True:
            try:
                local_data = local_connection.recv(BUFFER_SIZE)
                if not local_data:
                    break
                else:
                    # data received from local client will be fragmented and sent to tunnel.
                    # Once all fragments are sent, we will send special EOD to tunnel.
                    tunnel_client_socket = tunnel_client_fragmented_data_sender(tunnel_client_socket, local_data)

            except BlockingIOError:
                pass
            except KeyboardInterrupt:
                print("Server terminated by user")
                return
            except Exception as e:
                print("Exception: %s" % str(e))
                traceback.print_tb(e.__traceback__)
                return

            try:
                tunnel_data = FragTunnel.recv_data(tunnel_client_socket)
                if tunnel_data["status"] is None:
                    break
                else:
                    tunnel_client_socket.setblocking(1)  # need to switch to blocking mode

                    # try:
                    if tunnel_data["status"] == FragTunnel.SPECIAL_EOD:
                        # received EOD from tunnel, then join all fragments and send to local client
                        local_connection.sendall(incoming_fd_manager.get_data())
                        incoming_fd_manager.clear()
                        FragTunnel.send_eod(tunnel_client_socket)

                    # if received data, append to the list
                    elif tunnel_data["status"] == FragTunnel.DATA:
                        incoming_fd_manager.append_fragment(tunnel_data["raw_data"])

                        # send special ACK to tunnel
                        FragTunnel.send_ack(tunnel_client_socket)

                    # now time to close tunnel socket and establish a new connection for next time use
                    tunnel_client_socket.close()
                    tunnel_client_socket = None  # clear the socket
                    tunnel_client_socket = tunnel_client()

            except BlockingIOError:
                pass
            except KeyboardInterrupt:
                print("Server terminated by user")
                return
            except Exception as e:
                print("Exception: %s" % str(e))
                traceback.print_tb(e.__traceback__)
                return

    except KeyboardInterrupt:
        print("Server terminated by user")
        return
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
        return
    finally:
        # Close the connection
        tunnel_client_socket.close()
        local_connection.close()


# local server to accept incoming connections from local apps and establish a tunnel client
def local_server():
    local_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    local_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the address and port
    server_address = ('127.0.0.1', LOCAL_PORT)
    local_server_socket.bind(server_address)

    # Listen for incoming connections
    local_server_socket.listen(5)
    print("Local server listening on port %d" % LOCAL_PORT)

    try:
        while True:
            # Wait for a connection
            local_connection, local_client_address = local_server_socket.accept()
            log(f"Local connection from {local_client_address}")

            tunnel_client_socket = tunnel_client()

            # Create a thread to handle the client
            client_thread = threading.Thread(target=handle_local_client, args=(local_connection, tunnel_client_socket,))
            client_thread.daemon = True
            client_thread.start()
            client_thread.join()
    except KeyboardInterrupt:
        print("Local server terminated by user")
        return
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
        return


# a function to create a client socket and connect to the target server then return the socket
def local_client():
    global TARGET_PORT, TARGET_IP
    # Create a TCP/IP socket
    local_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server address and port
    server_address = (TARGET_IP, TARGET_PORT)
    local_client_socket.connect(server_address)
    log("Connected to target server")
    local_client_socket.setblocking(0)
    return local_client_socket


# tunnel server handler to handle tunnel client connections and local client connections to target server
def handle_tunnel_client(tunnel_connection):
    global TUNNEL_SERVER_IN_BUFFER, TUNNEL_SERVER_OUT_BUFFER, CLIENT_TO_TARGET_SOCK, TARGET_SET
    log("Handling new tunnel client connection")

    try:
        # create a list of fragmented data
        outgoing_fd_manager = FragmentManager()
        while True:
            try:
                if TUNNEL_SERVER_OUT_BUFFER.empty() is False:
                    tunnel_connection.setblocking(1)
                    while is_connected(tunnel_connection) is False:
                        time.sleep(0.005)

                    a = TUNNEL_SERVER_OUT_BUFFER.get()

                    tunnel_connection.sendall(a)
                    response = FragTunnel.recv_data(tunnel_connection)  # need to recv because of blocking

                    # just a hack to make it work
                    # some sleep delay is needed to prevent occasional partial data sent causing corrupted data
                    time.sleep(0.02)
            except BlockingIOError:
                pass
            except Exception as e:
                print("Exception: %s" % str(e))
                traceback.print_tb(e.__traceback__)

            if is_connected(CLIENT_TO_TARGET_SOCK):
                try:
                    local_data = CLIENT_TO_TARGET_SOCK.recv(BUFFER_SIZE)
                    if not local_data:
                        break
                    else:
                        outgoing_fd_manager.fragment_data(local_data)

                        # store into TUNNEL_SERVER_OUT_BUFFER to send it later fragment by fragment
                        for i in range(outgoing_fd_manager.get_fragment_count()):
                            b = outgoing_fd_manager.get_next_fragment()
                            TUNNEL_SERVER_OUT_BUFFER.put(b)

                        if ENCRYPTED_TUNNEL is True:
                            # if encryption is enabled, send encrypted special EOD to tunnel
                            TUNNEL_SERVER_OUT_BUFFER.put(encrypt_data(FragTunnel.SPECIAL_EOD.encode()))
                        else:
                            # send special EOD to tunnel
                            TUNNEL_SERVER_OUT_BUFFER.put(FragTunnel.SPECIAL_EOD.encode())

                        outgoing_fd_manager.clear()

                except BlockingIOError:
                    pass
                except OSError as e:
                    print(f"Error: %s" % e)
                    return

            if is_connected(tunnel_connection):
                try:
                    tunnel_connection.setblocking(0)
                    tunnel_data = FragTunnel.recv_data(tunnel_connection)
                    if tunnel_data["status"] is None:
                        break
                    else:
                        # fragmented data received from the tunnel will be appended until EDO.
                        # Once special EOD is received we will send the data to target server.
                        if tunnel_data["status"] == FragTunnel.SPECIAL_EOD:
                            joined_data = FragTunnel.join_fragments(TUNNEL_SERVER_IN_BUFFER)
                            CLIENT_TO_TARGET_SOCK.sendall(joined_data)
                            TUNNEL_SERVER_IN_BUFFER = queue.Queue()
                            FragTunnel.send_eod(tunnel_connection)

                        elif tunnel_data["status"] == FragTunnel.DATA:
                            TUNNEL_SERVER_IN_BUFFER.put(tunnel_data["raw_data"])
                            FragTunnel.send_ack(tunnel_connection)

                        elif tunnel_data["status"] == FragTunnel.TARGET_STRING:
                            if tunnel_set_target(tunnel_connection, tunnel_data) is False:
                                break

                except BlockingIOError:
                    pass
                except Exception as e:
                    print("Exception: %s" % str(e))
                    traceback.print_tb(e.__traceback__)

    except KeyboardInterrupt:
        print("Tunnel server terminated by user")
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)


# a function to handle receiving target set message, set the target and send ACK
def tunnel_set_target(tunnel_connection, tunnel_data=None):
    global TARGET_SET, TARGET_IP, TARGET_PORT, CLIENT_TO_TARGET_SOCK

    if tunnel_data is None:
        tunnel_data = FragTunnel.recv_data(tunnel_connection)

    if tunnel_data["status"] == FragTunnel.TARGET_STRING:
        message = tunnel_data["raw_data"].decode()
        log("Setting the target")

        target_str = message[23:]
        log("Received target ip %s and port %s" % (
            target_str.split(":")[0], target_str.split(":")[1]))

        TARGET_IP = target_str.split(":")[0]
        TARGET_PORT = int(target_str.split(":")[1])
        CLIENT_TO_TARGET_SOCK = local_client()
        TARGET_SET = True
        log("Target set")
        FragTunnel.send_ack(tunnel_connection)
        return True
    else:
        print("Error: Unexpected data received during setting target process")
        print("\r\nCheck if both tunnel client and server are using encoding or not. "
              "If they both using encoding with -e flag then make sure the secret is the same.")
        FragTunnel.send_err(tunnel_connection)
        return False


# tunnel server to accept incoming connections from tunnel clients and establish a connection to target server
def tunnel_server():
    global TUNNEL_SERVER_PORT, TARGET_SET, TARGET_IP, TARGET_PORT, CLIENT_TO_TARGET_SOCK
    # Create a TCP/IP socket
    tunnel_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tunnel_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Bind the socket to the address and port
    tunnel_server_address = ('0.0.0.0', TUNNEL_SERVER_PORT)
    tunnel_server_socket.bind(tunnel_server_address)

    # Listen for incoming connections
    tunnel_server_socket.listen(5)
    print("Tunnel server listening on port %d" % TUNNEL_SERVER_PORT)

    try:
        while True:
            # Wait for a connection
            tunnel_connection, tunnel_client_address = tunnel_server_socket.accept()
            log(f"Tunnel client connection from {tunnel_client_address}")

            if TARGET_SET is False:
                if tunnel_set_target(tunnel_connection) is False:
                    break

            else:
                # Create a thread to handle the client
                client_thread = threading.Thread(target=handle_tunnel_client,
                                                 args=(tunnel_connection,))
                client_thread.daemon = True
                client_thread.start()
                client_thread.join()
    except KeyboardInterrupt:
        print("Tunnel server terminated by user")
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
    finally:
        # Close the server socket
        TARGET_SET = False
        tunnel_server_socket.close()


# a function to create a tunnel client socket, send a message to set target and return the socket
def tunnel_client():
    global TUNNEL_SERVER_PORT, TUNNEL_SERVER_IP, TARGET_IP, TARGET_PORT, TARGET_SET

    # Create a TCP/IP socket
    tunnel_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server address and port
    tunnel_server_address = (TUNNEL_SERVER_IP, TUNNEL_SERVER_PORT)
    tunnel_client_socket.connect(tunnel_server_address)
    log("Connected to tunnel server")

    if TARGET_SET is False:
        FragTunnel.send_target_set_msg(tunnel_client_socket, TARGET_IP, TARGET_PORT)

        response = FragTunnel.recv_data(tunnel_client_socket)
        if response["status"] == FragTunnel.SPECIAL_ACK:
            log("Target server was set")
            TARGET_SET = True
        else:
            log("Error: Setting target server failed")

        tunnel_client_socket.close()
        return tunnel_client()
    else:
        tunnel_client_socket.setblocking(0)
        return tunnel_client_socket


def usage():
    print("\r\nUsage: %s -p port -t target ip:port -T tunnel endpoint ip:port -b bind ip:port -e secret\r\n" % \
          sys.argv[0])
    print("-h --help        help")
    print("-p --port        port to listen for a local app to connect")
    print("-t --target      target's ip:port")
    print("-T --Tunnel to   tunnel server's ip:port")
    print("-b --bind        tunnel server listen ip:port")
    print("-e --encrypt     encrypt/encode tunnel traffic using the secret provided with this flag")
    print("-v --verbose     verbose mode")

    sys.exit(0)


if __name__ == "__main__":
    target, tunnel_endpoint, bind = str(""), str(""), str("")

    if not len(sys.argv[1:]):
        usage()
        # read the commandline options

    argumentList = sys.argv[1:]

    # Options
    options = "h:t:T:p:b:e:v"

    # Long options
    long_options = ["help", "target", "tunnelTo", "port=", "bind", "encrypt", "verbose"]

    try:
        arguments, values = getopt.getopt(argumentList, options, long_options)
    except getopt.GetoptError as err:
        print(str(err))
        usage()
        sys.exit(0)

    # checking each argument
    for currentArgument, currentValue in arguments:
        if currentArgument in ("-h", "--help"):
            usage()
        elif currentArgument in ("-t", "--target"):
            target = currentValue
        elif currentArgument in ("-T", "--tunnelTo"):
            tunnel_endpoint = currentValue
        elif currentArgument in ("-p", "--port"):
            LOCAL_PORT = int(currentValue)
        elif currentArgument in ("-b", "--bind"):
            bind = currentValue
        elif currentArgument in ("-e", "--encrypt"):
            ENCRYPTED_TUNNEL = True
            SECRET_KEY = currentValue.encode()
        elif currentArgument in ("-v", "--verbose"):
            print("Verbose mode")
            VERBOSE = True
        else:
            assert False, "Unhandled Option"

    try:
        if len(target) > 0:
            target_list = target.split(":")
            if not target_list[0]:
                TARGET_IP = "127.0.0.1"
            else:
                TARGET_IP = target_list[0]
            TARGET_PORT = int(target_list[1])
        if len(tunnel_endpoint) > 0:
            tunnel_endpoint_list = tunnel_endpoint.split(":")
            if not tunnel_endpoint_list[0]:
                TUNNEL_SERVER_IP = "127.0.0.1"
            else:
                TUNNEL_SERVER_IP = tunnel_endpoint_list[0]
            TUNNEL_SERVER_PORT = int(tunnel_endpoint_list[1])
        if len(bind) > 0:
            bind_list = bind.split(":")
            if not bind_list[0]:
                BIND_IP = "0.0.0.0"
            else:
                BIND_IP = bind_list[0]
            TUNNEL_SERVER_PORT = int(bind_list[1])
            log("bind port is %d" % TUNNEL_SERVER_PORT)
    except KeyboardInterrupt:
        print("Exiting...")
        sys.exit(0)
    except Exception as e:
        print("Exception: %s" % str(e))
        traceback.print_tb(e.__traceback__)
        sys.exit(0)

    # tunnel client side
    if LOCAL_PORT > 0 and len(tunnel_endpoint) > 0 and len(target) > 0:
        if len(TUNNEL_SERVER_IP) > 0 and TUNNEL_SERVER_PORT > 0 and len(
                TARGET_IP) > 0 and TARGET_PORT > 0:
            local_server()

    # tunnel server side
    if len(BIND_IP) > 0 and TUNNEL_SERVER_PORT > 0:
        try:
            print("Binding fragmented server on %s:%d" % (BIND_IP, TUNNEL_SERVER_PORT))
            tunnel_server()
        except KeyboardInterrupt:
            print("Exiting...")
            sys.exit(0)

    try:
        # Wait for the threads to finish
        while threading.active_count() > 1:
            pass
    except KeyboardInterrupt:
        print("Exiting...")
