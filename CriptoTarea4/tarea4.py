import subprocess
import os
import socket
import donna25519
from donna25519 import PrivateKey
from donna25519 import PublicKey
import hashlib
import time
import pickle

out = subprocess.Popen(['hashcat','-a','0','-m','0','./ArchivoTarea4/Hashes/archivo_1','./ArchivoTarea4/diccionarios/diccionario_2.dict','-o','./resultados/resultado1.txt','--potfile-disable', '--force'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

stdout,stderr = out.communicate()

print(stdout)
print(stderr)

out2 = subprocess.Popen(['hashcat','-a','0','-m','10','./ArchivoTarea4/Hashes/archivo_2','./ArchivoTarea4/diccionarios/diccionario_2.dict','-o','./resultados/resultado2.txt','--potfile-disable', '--force'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

stdout,stderr = out2.communicate()

print(stdout)
print(stderr)

out3 = subprocess.Popen(['hashcat','-a','0','-m','10','./ArchivoTarea4/Hashes/archivo_3','./ArchivoTarea4/diccionarios/diccionario_2.dict','-o','./resultados/resultado3.txt','--potfile-disable', '--force'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

stdout,stderr = out3.communicate()

print(stdout)
print(stderr)

out4 = subprocess.Popen(['hashcat','-a','0','-m','1000','./ArchivoTarea4/Hashes/archivo_4','./ArchivoTarea4/diccionarios/diccionario_2.dict','-o','./resultados/resultado4.txt','--potfile-disable', '--force'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

stdout,stderr = out4.communicate()

print(stdout)
print(stderr)


out5 = subprocess.Popen(['hashcat','-a','0','-m','1800','./ArchivoTarea4/Hashes/archivo_5','./ArchivoTarea4/diccionarios/diccionario_2.dict','-o','./resultados/resultado5.txt','--potfile-disable', '--force'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

stdout,stderr = out5.communicate()

print(stdout)
print(stderr)


for resultado in range(1,6):
    print(resultado)
    Result = open("./resultados/resultado"+str(resultado)+".txt")

    passwords = []
    for i in Result:
        password = i.strip().split(":")[-1]
        passwords.append(password)

    nuevosHashes = []
    t0 = time.clock()
    for p in passwords:

        salt = os.urandom(32)
        dk = hashlib.pbkdf2_hmac('sha512',p.encode('utf-8'),salt,10000, dklen=64)
        nuevosHashes.append(dk.hex())

    print("\n\n Usando sha512 con 10000 rondas, se logro hashear las contraseñas en:\n ",time.clock()-t0)
    archivo=open("./NuevosHashes/sha3-512_"+str(resultado)+".txt","w")

    for hash in nuevosHashes:
        archivo.write(str(hash) + "\n")
    archivo.close()



HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b'Hello, world')
    data = s.recv(1024)
    data=pickle.loads(data)


print('Datos recibidos: ', repr(data))


llavePublica=PublicKey(data)
llavePrivada=PrivateKey().do_exchange(llavePublica)
print("\n")
print(llavePublica)
print("\n")
print(llavePrivada)
