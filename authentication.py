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
import threading


serverPublicKey = b''
serverSecretKey = b''

database = sys.argv[1]
usersToPasswords = {}
publicKeyValue = {}
privateKeyValue = {}
lock = threading.Lock()


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
    if msg.client_hello.major_version != 3:
        return error_message("Wrong version")
    response = nstp_v3_pb2.NSTPMessage()
    response.server_hello.major_version = 3
    response.server_hello.minor_version = 1
    response.server_hello.user_agent = "hello client"
    response.server_hello.public_key = bytes(serverPublicKey) #serverPublicKey.encode()
    return response

def decryptMessage(msg, keys):
    ciphertext = msg.encrypted_message.ciphertext
    nonce = msg.encrypted_message.nonce
    try:
        plaintextBytes = nacl.bindings.crypto_secretbox_open(ciphertext, nonce, keys[0])
        decrypted = nstp_v3_pb2.DecryptedMessage()
        decrypted.ParseFromString(plaintextBytes)
        print("DECRYPTED MESSAGE\n", decrypted)
        return decrypted
    except nacl.exceptions.CryptoError:
        print("Bad key")
        return error_message("Failed to decrypt given message")

def encryptMessage(msg, keys):
    nonce = nacl.utils.random(24)
    encryptedBytes = nacl.bindings.crypto_secretbox(msg.SerializeToString(), nonce, keys[1])
    response = nstp_v3_pb2.NSTPMessage()
    response.encrypted_message.ciphertext = encryptedBytes
    response.encrypted_message.nonce = nonce
    return response

def authentication_response(decision, user, authenticated):
    response = nstp_v3_pb2.DecryptedMessage()
    response.auth_response.authenticated = decision
    return response, user, authenticated

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

def authorization_request(msg, authenticated):
    username = msg.auth_request.username
    password = msg.auth_request.password

    print(username)
    print(password)

    if authenticated:
        return error_message("A user has already been authenticated")
    elif username not in usersToPasswords.keys():
        return authentication_response(False, username, False)
    else:
        storedPassword = usersToPasswords[username]
        result = comparePasswords(password, storedPassword)
        if result:
            authenticated = True
        return authentication_response(result, username, authenticated)

def store_response(hashedValue):
    response = nstp_v3_pb2.DecryptedMessage()
    response.store_response.hash = hashedValue
    response.store_response.hash_algorithm = 0
    return response

def store_request(msg, user):
    global publicKeyValue
    global privateKeyValue
    key = msg.store_request.key
    value = msg.store_request.value
    public = msg.store_request.public
    
    lock.acquire()
    if public:
        publicKeyValue[key] = value
    else:
        # TODO if it is not public
        if user in privateKeyValue.keys():
            privateKeyValue[user][key] = value
        else:
            privateKeyValue[user] = {}
            privateKeyValue[user][key] = value
    lock.release()

    hashedValue = value
    return store_response(hashedValue)

def load_response(value):
    response = nstp_v3_pb2.DecryptedMessage()
    response.load_response.value = value
    return response

def load_request(msg, user):
    global publicKeyValue
    global privateKeyValue
    key = msg.load_request.key
    public = msg.load_request.public
    value = b''

    lock.acquire()
    if public:
        if key in publicKeyValue.keys():
            value = publicKeyValue[key]
    else:
        print('PRIVATE LOAD REQUEST')
        if user in privateKeyValue.keys():
            if privateKeyValue[user].get(key) != None:
                value = privateKeyValue[user][key]
    lock.release()
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

def messageType(msg, authenticated, user):
    if msg.HasField("auth_request"):
        return authorization_request(msg, authenticated)
    elif msg.HasField("ping_request"):
        return ping_request(msg), user, authenticated
    elif msg.HasField("load_request"):
        return load_request(msg, user), user, authenticated
    elif msg.HasField("store_request"):
        return store_request(msg, user), user, authenticated

def recv_all(s,n):
    xs = b""
    while len(xs) < n:
        x = s.recv(n-len(xs))
        if len(x) == 0:
            break
        xs += x
    return xs

def connection_thread(c, addr):
    global serverPublicKey
    global serverSecretKey
    print("REMOTE: ", addr[0])
    
    clientPublicKey = b''
    lengthInBytes = recv_all(c, 2)
    if len(lengthInBytes) == 0:
        c.close()
    length = struct.unpack("!H", lengthInBytes)[0]
    msg = recv_all(c, length)
    read = nstp_v3_pb2.NSTPMessage()
    read.ParseFromString(msg)
    print(read)
    end = False
    attempts = False
    authenticated = False
    user = ""

    if read.HasField("client_hello"):
        clientPublicKey = read.client_hello.public_key
        #print("client public key ", clientPublicKey)
        if clientPublicKey == b'':
            response = error_message("Must include a public_key")
            sentMsg = response.SerializeToString()
            sentLen = struct.pack("!H", len(sentMsg))
            c.sendall(sentLen + sentMsg)
            c.close()
            return 0
        response = sendServerHello(read)
        keys = nacl.bindings.crypto_kx_server_session_keys(serverPublicKey.encode(),
            serverSecretKey.encode(), clientPublicKey)
    else:
        # TODO this needs to be tested
        response = error_message("Must send a client hello first")
        end = True

    sentMsg = response.SerializeToString()
    sentLen = struct.pack("!H", len(sentMsg))
    c.sendall(sentLen + sentMsg)
    if end:
        c.close()
        return 0

    while True:
        lengthInBytes = recv_all(c, 2)
        if len(lengthInBytes) == 0:
            break
        print(lengthInBytes)
        length = struct.unpack("!H", lengthInBytes)[0]
        msg = recv_all(c, length)
        #print(msg)
        read = nstp_v3_pb2.NSTPMessage()
        read.ParseFromString(msg)
        print("READ", read)

        plaintextResponse = ""
        if read.HasField("encrypted_message"):
            decryptedMsg = decryptMessage(read, keys)
            if decryptedMsg.HasField("error_message"):
                plaintextResponse = decryptedMsg
            elif decryptedMsg.HasField("auth_request"):
                # TODO should this be based off of IP addresses
                # TODO should this be cleared?
                attempts += 1
                if attempts > 10:
                    print("ERROR")
                    plaintextResponse = error_message("Too many attempts.")
                else:
                    plaintextResponse, user, authenticated = messageType(decryptedMsg, authenticated, user)
            else:
                plaintextResponse, user, authenticated = messageType(decryptedMsg, authenticated, user)
            print("PLAINTEXT RESPONSE\n", plaintextResponse)
            # TODO encrypted or unencrypted?
            response = encryptMessage(plaintextResponse, keys)
        else:
            print("wrong message type set")
            plaintextResponse = error_message("Wrong message type sent")
            response = encryptMessage(plaintextResponse, keys)

        sentMsg = response.SerializeToString()
        sentLen = struct.pack("!H", len(sentMsg))
        c.sendall(sentLen + sentMsg)    
        if plaintextResponse.HasField("error_message"):
            print("Connection with client has been closed")
            break
    c.close()
    return 0

def main():
    global serverPublicKey
    global serverSecretKey
    print("RUNNING")
    readDatabase()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 22300
    host = '0.0.0.0'
    s.bind((host, port))
    s.listen(5)
    s.settimeout(10)
    
    serverSecretKey = PrivateKey.generate()
    serverPublicKey = serverSecretKey.public_key

    while True:
        try:
            c, addr = s.accept()
            print("Spawning thread")
            t = threading.Thread(target=connection_thread, args=(c, addr))
            t.start()
        except socket.timeout:
            break
    s.close()
    return 0

main()

