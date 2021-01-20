# author: Valentyn Kuts

from Crypto.Cipher import AES
# first of all import the socket library
import socket

# next create a socket object
s = socket.socket()
print("Socket successfully created")

# reserve a port on your computer in our
# case it is 22348 but it can be anything
port = 22348

# Next bind to the port
# we have not typed any ip in the ip field
# instead we have inputted an empty string
# this makes the server listen to requests
# coming from other computers on the network
s.bind(('', port))
print("socket binded to %s" % port)

# put the socket into listening mode
s.listen(5)
print("socket is listening")

msg = 'Thank you for connecting'

# a forever loop until we interrupt it or
# an error occurs
while True:
    # Establish connection with client.
    conn, addr = s.accept()
    print('Got connection from', addr)

    # data = conn.recv(1024).decode("utf-8")
    data = conn.recv(1024)
    # print(data)

    cipher = AES.new("Sixteen byte key")
    encrypted_data = cipher.decrypt(data)
    print(encrypted_data)
    # string to bytes
    # b = bytes(msg, 'utf-8')
    b = msg.encode('utf-8')

    # send a thank you message to the client.
    conn.send(b)

    # Close the connection with the client
    conn.close()
