from garak.cli import main
from socket import socket, AF_INET, SOCK_STREAM
import sys

ADDRESS = "localhost"
PORT = 45345

def run():
    garak_socket = socket(AF_INET, SOCK_STREAM)
    garak_socket.bind((ADDRESS, PORT))
    garak_socket.listen()
    # Client needs to tell the api which port to send the output to.
    while True:
        client_socket, client = garak_socket.accept()

        arguments = client_socket.recv(1024).decode()
        arguments = arguments.split()

        client_address = client[0]
        client_port = int(arguments[0])

        # This just makes sure that the output of the cli is returned to the client.
        def redirectOut(port=0, host=0):
            if port == 0 or host == 0:
                raise ValueError("Client port or address weren't found")
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect((host, port))
            with sock.makefile("w") as file:
                sys.stdout = file
                main(arguments[1:])
            return sock

        redirectOut(client_port, client_address)
