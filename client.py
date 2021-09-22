import socket
import threading
import hashlib

if __name__ == "__main__":
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"
    host = "127.0.0.1"
    port = 8080

    # Read in stored RSA keys here
    # with open('client_private.pem', 'rb'):
    #     pass
    # with open('client_public.pem', 'rb'):
    #     pass
    # Otherwise generate new RSA keys here

    check = False
    server = None

    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.connect((host, port))
        check = True
    except:
        print("[!] Check Server Address or Port\n")

    if check and server:
        print("\n[!] Connection Successful\n")
        # Send Public RSA key here to initiate handshake
        server.send(b'test')
        # Receive server RSA key here to continue handshake
        server_received = server.recv(4072)
        server.send(b'test again')


