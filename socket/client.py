# author: Valentyn Kuts

from Crypto.Cipher import AES
# Import socket module
import socket

# Create a socket object
s = socket.socket()

# Define the port on which you want to connect
port = 22348

# connect to the server on local computer
s.connect(('127.0.0.1', port))

# msg = 'Hello from 127.0.0.1 '
# # string to bytes
# # b_msg = bytes(msg, 'utf-8')
# b_msg = msg.encode('utf-8')
# s.send(b_msg)
#
# msg1 = ' :-)'
# b_msg1 = msg1.encode('utf-8')
# s.send(b_msg1)

cipher = AES.new("Sixteen byte key")
encrypted_data = cipher.encrypt("Hello, it is from 127.0.0.1  :-)")
s.send(encrypted_data)

# receive data from the server
print(s.recv(1024))

# close the connection
s.close()
