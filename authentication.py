#!/usr/bin/env python3
import socket
import struct
import nstp_v3_pb2
import nacl
from nacl.public import PublicKey, PrivateKey, Box

clientPublicKey = b''
serverPublicKey = b''
serverSecretKey = b''

def sendServerHello(msg):
    global serverPublicKey
    response = nstp_v3_pb2.NSTPMessage()
    response.server_hello.major_version = 3
    response.server_hello.minor_version = 1
    response.server_hello.user_agent = "hello client"
    response.server_hello.public_key = bytes(serverPublicKey) #serverPublicKey.encode()
    return response

def decryptMessage(msg):
    global serverSecretKey
    global clientPublicKey
    ciphertext = msg.encrypted_message.ciphertext
    nonce = msg.encrypted_message.nonce
    print("CIPHER ", ciphertext)
    print("NONCE: ", nonce)
    
    print("Later secret key ", serverSecretKey)
    print("Later public key ", clientPublicKey)
    box = Box(serverSecretKey, PublicKey(clientPublicKey))
    plaintext = box.decrypt(ciphertext)
    print(plaintext)
    return 0

def recv_all(s,n):
    xs = b""
    while len(xs) < n:
        x = s.recv(n-len(xs))
        if len(x) == 0:
            break
        xs += x
    return xs

def main():
    global serverPublicKey
    global serverSecretKey
    global clientPublicKey
    print("RUNNING")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 22300
    host = '0.0.0.0'
    s.bind((host, port))
    s.listen(5)
    s.settimeout(10)
    
    serverSecretKey = PrivateKey.generate()
    print(serverSecretKey)
    serverPublicKey = serverSecretKey.public_key
    print(serverPublicKey)
    c, addr = s.accept()
    print("Got one")

    while True:
        try:
            #c, addr = s.accept()
            #print("Got one")
            lengthInBytes = recv_all(c, 2)
            print(lengthInBytes)
            length = struct.unpack("!H", lengthInBytes)[0]
            msg = recv_all(c, length)
            #print(msg)
            read = nstp_v3_pb2.NSTPMessage()
            read.ParseFromString(msg)
            print(read)

            if read.HasField("client_hello"):
                clientPublicKey = read.client_hello.public_key
                response = sendServerHello(read)
            elif read.HasField("encrypted_message"):
                decryptMessage(read)
                # TODO remove this return
                return 0
               
            print(response)
            sentMsg = response.SerializeToString()
            print(len(sentMsg))
            sentLen = struct.pack("!H", len(sentMsg))
            c.sendall(sentLen + sentMsg)    

        except socket.timeout:
            break
    s.close()
    return 0

main()

