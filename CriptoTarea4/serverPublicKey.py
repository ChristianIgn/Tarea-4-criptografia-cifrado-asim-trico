import socket
from donna25519 import PrivateKey
from donna25519 import PublicKey
import base64
import pickle

variable_1=PrivateKey()
# se muestra la llave privada generada
print(variable_1)
variable_2=PrivateKey().get_public().public

# se muestra la llave publica de 32 bytes correspondiente a la PrivateKey
print(variable_2)
pk=pickle.dumps(variable_2)

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            if not data:
                break

            # se envía por medio del socket en bloque la llave publica de 32 bytes
            conn.sendall(pk)
