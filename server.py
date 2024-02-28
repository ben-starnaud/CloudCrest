#Server script is responsible to create the server and handles
#connections and disconnections from files
#Allows clients to connect to each other directly
#so that they upload/download files 
import socket
import threading

# global parallel socket and IPaddress arrays 
CLIENTLIST = []
CLIENT_IP_LIST = []
CLIENT_USERNAME_LIST = []
SERVER_COMMS_PORT = 9999
SERVER_HOST_IP = "25.22.165.213"


#handles the clients that are connecting and sending messages out 
#to clients letting them know who is connected
#
class ClientThread(threading.Thread):
    #initializes the thread for letting clients connect
    def __init__(self, client_address, client_socket, client_list):
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.client_address = client_address

        self.client_list = client_list
        print("Newest connection IP Address: ", client_address) #

    def broadcast(self, message):
        for clientSocket in self.client_list:
            clientSocket.send(message)

    # sends the owner and requester of the file the message to initiate a file transfer
    def let_bind(self, message, IPowner, IPreq):
        # print(self.client_list)
        # print(self.client_address)
        # print(IPowner+" "+IPreq)
        print(CLIENT_IP_LIST)
        print("IPowner = "+ IPowner)
        print("IPreq = "+IPreq)
        for i in range(0, len(CLIENT_IP_LIST)):
            if (CLIENT_IP_LIST[i])[0] == IPowner: #check if client ip is part of connected clients
                # send msg to owner
                print("IPowner found")
                ownerSocket = CLIENTLIST[i]
                ownerSocket.send(message.encode())
                continue
            if (CLIENT_IP_LIST[i])[0] == IPreq:
                # send msg to owner
                print("IPreq found")
                requesterSocket = CLIENTLIST[i]
                requesterSocket.send(message.encode())


#handles disconnections for clients and requests from clients
    def run(self):
        def find_nth(haystack, needle, n):
            start = haystack.find(needle)
            while start >= 0 and n >= 1:
                start = haystack.find(needle, start+len(needle))
                n -= 1
            return start
        
        while True:
            data = self.client_socket.recv(1024)
            message = data.decode()
            print("server message received: "+message) #server acks message from client

            if not message:
                self.client_list.remove(self.client_socket)
                print("Client disconnected...")
                break

            elif message[0:3] == "add":             #handles an upload from client
                self.broadcast(message.encode())
                pass
            
            elif(message[0:3] == 'req'):        #handles request from client

                print("\nreq message: "+message+"\n")

                end = find_nth(message, ":", 1)
                IpBegin = end+1
                IpEnd = find_nth(message, ":", 2)
                IPowner = message[IpBegin:IpEnd]
                IPreq = message[IpEnd+1: len(message)]

                self.let_bind(message, IPowner, IPreq)
            elif message[0:3] == "tmp":
                # its a username request
                rqUsername = message[3:len(message)]
                if rqUsername in CLIENT_USERNAME_LIST:
                    self.client_socket.send("username taken".encode())
                else:
                    ClientThread.THIS_THREAD_USERNAME = rqUsername
                    CLIENT_USERNAME_LIST.append(rqUsername)
                    print(CLIENT_USERNAME_LIST)

            else: # broadcast messages received
                self.broadcast(message.encode())

        self.client_socket.close()
        # remove the clients after connection is lost


#starts the server 
class Server:
    def __init__(self, host=SERVER_HOST_IP, port=SERVER_COMMS_PORT):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.client_list = []
        self.client_addresses = []

    def start(self):
        self.server_socket.listen()
        print(f"Server started and listening on {self.host}:{self.port}")
        
        while True:
            client_socket, client_address = self.server_socket.accept()     #adds new clients

            self.client_list.append(client_socket)
            self.client_addresses.append(client_address)
            CLIENTLIST.append(client_socket)
            CLIENT_IP_LIST.append(client_address)

            new_thread = ClientThread(client_address, client_socket, self.client_list)
            new_thread.start()

server = Server()
server.start()