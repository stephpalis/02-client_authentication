#!/usr/bin/env python3
import socket
import struct
import nstp_v3_pb2
import nacl
from nacl.public import PublicKey, PrivateKey, Box
import nacl.bindings
import nacl.secret
import sys
import hashlib
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt, argon2

clientPublicKey = b''
serverPublicKey = b''
serverSecretKey = b''
keys = []
user = ""
authenticated = False
tries = 0

database = sys.argv[1]
usersToPasswords = {}
publicKeyValue = {}
privateKeyValue = {}


def readDatabase():
    global usersToPasswords
    f = open(database, 'r')
    lines = f.readlines()
    for i in lines:
        data = i.split(":")
        usersToPasswords[data[0]] = data[1][:-1]
    f.close()
    print(usersToPasswords)

def error_message(reason):
    response = nstp_v3_pb2.NSTPMessage()
    response.error_message.error_message = reason
    return response

def sendServerHello(msg):
    global serverPublicKey
    response = nstp_v3_pb2.NSTPMessage()
    response.server_hello.major_version = 3
    response.server_hello.minor_version = 1
    response.server_hello.user_agent = "hello client"
    response.server_hello.public_key = bytes(serverPublicKey) #serverPublicKey.encode()
    return response

def decryptMessage(msg, keys):
    global serverSecretKey
    global clientPublicKey
    ciphertext = msg.encrypted_message.ciphertext
    nonce = msg.encrypted_message.nonce
    #print("CIPHER ", type(ciphertext))
    #print("NONCE: ", type(nonce))
    
    #print("Later secret key ", type(serverSecretKey))
    #print("Later public key ", len(clientPublicKey))
    #box = Box(serverSecretKey, PublicKey(clientPublicKey))
    #plaintext = box.decrypt(ciphertext, nonce)
    #keys = nacl.bindings.crypto_kx_server_session_keys(serverPublicKey.encode(), serverSecretKey.encode(), clientPublicKey)
    plaintextBytes = nacl.bindings.crypto_secretbox_open(ciphertext, nonce, keys[0])
    decrypted = nstp_v3_pb2.DecryptedMessage()
    decrypted.ParseFromString(plaintextBytes)
    print("DECRYPTED MESSAGE\n", decrypted)
    return decrypted

def encryptMessage(msg, keys):
    nonce = nacl.utils.random(24)
    encryptedBytes = nacl.bindings.crypto_secretbox(msg.SerializeToString(), nonce, keys[1])
    response = nstp_v3_pb2.NSTPMessage()
    response.encrypted_message.ciphertext = encryptedBytes
    response.encrypted_message.nonce = nonce
    return response

def authentication_response(decision):
    response = nstp_v3_pb2.DecryptedMessage()
    response.auth_response.authenticated = decision
    return response

def comparePasswords(password, stored):
    hashAlg = stored[1:].split("$")[0]
    if hashAlg == "1":
        #MD5
        return md5_crypt.verify(password, stored)
    elif hashAlg == "5":
        #SHA256
        return sha256_crypt.verify(password, stored)
    elif hashAlg == "6":
        #SHA512
        return sha512_crypt.verify(password, stored)
    elif hashAlg == "argon2id":
        #Argon
        # TODO check
        return argon2.verify(password, stored)

def authorization_request(msg):
    global user
    global authenticated
    username = msg.auth_request.username
    password = msg.auth_request.password

    print(username)
    print(password)

    if authenticated:
        return error_message("A user has already been authenticated")
    elif username not in usersToPasswords.keys():
        return authentication_response(False)
    else:
        storedPassword = usersToPasswords[username]
        result = comparePasswords(password, storedPassword)
        if result:
            user = username
            authenticated = True
        return authentication_response(result)

def store_response(hashedValue):
    response = nstp_v3_pb2.DecryptedMessage()
    response.store_response.hash = hashedValue
    response.store_response.hash_algorithm = 0
    return response

def store_request(msg):
    global publicKeyValue
    global privateKeyValue
    global user
    key = msg.store_request.key
    value = msg.store_request.value
    public = msg.store_request.public
    
    if public:
        publicKeyValue[key] = value
    else:
        # TODO if it is not public
        if user in privateKeyValue.keys():
            privateKeyValue[user][key] = value
        else:
            privateKeyValue[user] = {}
            privateKeyValue[user][key] = value

    hashedValue = value
    return store_response(hashedValue)

def load_response(value):
    response = nstp_v3_pb2.DecryptedMessage()
    response.load_response.value = value
    return response

def load_request(msg):
    global publicKeyValue
    global privateKeyValue
    global user
    key = msg.load_request.key
    public = msg.load_request.public
    value = b''

    if public:
        if key in publicKeyValue.keys():
            value = publicKeyValue[key]
    else:
        print('PRIVATE LOAD REQUEST')
        if user in privateKeyValue.keys():
            if privateKeyValue[user].get(key) != None:
                value = privateKeyValue[user][key]

    return load_response(value)

def ping_response(data):
    response = nstp_v3_pb2.DecryptedMessage()
    response.ping_response.hash = data
    return response

def ping_request(msg):
    # TODO check if it should be == 0 or == IDENTITY
    data = msg.ping_request.data
    hashAlg = msg.ping_request.hash_algorithm

    if hashAlg == 0:
        # IDENTITY
        hashed = data
    elif hashAlg == 1:
        # SHA256
        hashed = hashlib.sha256(data).digest()
    elif hashAlg == 2:
        # SHA512
        hashed = hashlib.sha512(data).digest()
    else:
        # wrong hash
        return error_message("Invalid hash algorithm")

    return ping_response(hashed)

def messageType(msg):
    if msg.HasField("auth_request"):
        return authorization_request(msg)
    elif msg.HasField("ping_request"):
        return ping_request(msg)
    elif msg.HasField("load_request"):
        return load_request(msg)
    elif msg.HasField("store_request"):
        return store_request(msg)

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
    global tries
    print("RUNNING")
    print(database)
    readDatabase()
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
    #c, addr = s.accept()
    #print("Got one")

    while True:
        try:
            c, addr = s.accept()
            t = threading.Thread(target=connection_thread, args=(c, addr))
            t.start()


            print("REMOTE: ", addr[0])
            while True:
                #c, addr = s.accept()
                #print("Got one")
                lengthInBytes = recv_all(c, 2)
                if len(lengthInBytes) == 0:
                    break
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
                    keys = nacl.bindings.crypto_kx_server_session_keys(serverPublicKey.encode(), 
                        serverSecretKey.encode(), clientPublicKey)
                
                # TODO make sure send a client_hello before this
                elif read.HasField("encrypted_message"):
                    decryptedMsg = decryptMessage(read, keys)
                    if decryptedMsg.HasField("auth_request"):
                        tries += 1
                        if tries > 10:
                            print("ERROR")
                            plaintextResponse = error_message("Too many tries.")
                        else:
                            plaintextResponse = messageType(decryptedMsg)
                            print("PLAINTEXT RESPONSE\n", plaintextResponse)
                    else:
                        print("PLAINTEXT RESPONSE\n", plaintextResponse)
                        plaintextResponse = messageType(decryptedMsg)
                    # TODO encrypted or unencrypted?
                    response = encryptMessage(plaintextResponse, keys)

                print("continue worked properly")
                sentMsg = response.SerializeToString()
                sentLen = struct.pack("!H", len(sentMsg))
                c.sendall(sentLen + sentMsg)    
                if response.HasField("error_message"):
                    print("Connection with client has been closed")
                    c.close()
                    tries = 0
        except socket.timeout:
            break
    s.close()
    return 0

main()

