import socket
import os
import signal
import threading


def get_ip_address():
    # ip = requests.get('https://checkip.amazonaws.com').text.strip()
    return '0.0.0.0'


def send_message(socket_client):
    while True:
        msg = input("\n[>] ENTER YOUR MESSAGE : ")
        socket_client.send(bytes(msg))
        if msg == FLAG_QUIT:
            os.kill(os.getpid(), signal.SIGKILL)


def ConnectionSetup():
    while True:
        if check is True:
            client, address = server.accept()
            print("\n[!] One client is trying to connect...")
            # get client public key and the hash of it
            client_recieved = client.recv(2048)
            print(f"RECEIVED DATA: {client_recieved}")

            msg = input("\n[>] ENTER YOUR MESSAGE : ")
            client.send(bytes(msg, 'utf-8'))
            if msg == FLAG_QUIT:
                os.kill(os.getpid(), signal.SIGKILL)


if __name__ == "__main__":
    CONNECTION_LIST = []
    FLAG_READY = "Ready"
    FLAG_QUIT = "quit"

    # Read in stored RSA keys here
    # with open('server_private.pem', 'rb'):
    #     pass
    # with open('server_public.pem', 'rb'):
    #     pass
    # Otherwise generate new RSA keys here

    host = get_ip_address()
    port = 8080

    print(f"\n[!] Server IP {host} & PORT {port}")
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)

    print("\n[!] Server Connection Successful")

    check = True
    # accept clients
    threading_accept = threading.Thread(target=ConnectionSetup)
    threading_accept.start()
