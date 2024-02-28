# This program communicates with the server to send files from peer to peer
# a client can make a file availible for downloading by uploading the filename
# Another client can download an availible file by requesting the filename
# if the file isnot availible it requests the closest match oterwise the client 
# is notified of an invalid filename
import threading
import socket
import time
import struct
import tkinter as tk
import os
import time
from tkinter import Toplevel
from tkinter import *
from tkinter import filedialog
from tkinter import ttk
from PIL import ImageTk, Image
from difflib import get_close_matches


HOST = ''
PORT = 1234
TCP_PORT = 1235
SERVER_COMMS_PORT = 9999
SERVER_HOST = '25.22.165.213'
THIS_CLIENT_IP = '25.22.165.213'
BLAST_SIZE = 1024
TIMEOUT = 0.1
TERMINATION_PACKET = b'0000'
TO = 0
TOTAL = 0
T2 = 0
TOTAL2 = 0
PROGRESS = 0


# Send a termination packet to indicate that it is the end of the file
def send_termination_packet(tcp_conn):
    tcp_conn.sendall(TERMINATION_PACKET)


# Receive files over TCP
def TCP_receive(progress_bar, update_progress):
    TCP_receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket to receive the file
    TCP_receive_socket.bind((THIS_CLIENT_IP, PORT))
    TCP_receive_socket.listen(1)
    while True:
        peer, peer_addr = TCP_receive_socket.accept() # Accept an incoming connection
        full_path = peer.recv(1024).decode()
        filename = os.path.basename(full_path) # Get the file's full path, name, and size
        file_size = int(peer.recv(1024).decode())
        progress_bar["maximum"] = file_size # Set the progress bar's maximum value to the file size
        print(filename)
        try:
            with open(filename, 'wb') as f: # Save the received file
                received_bytes = 0
                while True:
                    filedata = peer.recv(1024)
                    if not filedata:
                        break
                    received_bytes += len(filedata)
                    update_progress(received_bytes) # Update the progress bar 
                    f.write(filedata)
            peer.close() # Close the connection
            print(f"File '{filename}' received from {peer_addr[0]} with TCP") 
            progress_bar['value'] = 0
            root.update_idletasks()
        except Exception as e:
            print(f"Error receiving file '{filename}': {e}")

#send files over TCP
def TCP_send(progress_bar, recipient, filetosend):
    TO = time.time()
    filename = filetosend
    print(filetosend)
    try:
        with open(filetosend, 'rb') as f: # Read the file to be sent
            file_size = os.path.getsize(filetosend)
            filedata = f.read() 
            progress_bar['maximum'] = file_size # Set the progress bar's maximum value to the file size
            try:
                TCP_send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Create a TCP socket to send the file
                TCP_send_socket.connect((recipient, PORT))
                TCP_send_socket.send(filename.encode()) # Send the file name and size
                time.sleep(1)
                TCP_send_socket.send(str(file_size).encode())
                time.sleep(1)
                
                # Send the file in chunks
                bytes_sent = 0
                with open(filetosend, 'rb') as file:
                    while (chunk := file.read(1024)):
                        TCP_send_socket.sendall(chunk)
                        bytes_sent += len(chunk)
                        progress_bar['value'] = bytes_sent
                        root.update_idletasks()
                t1 = time.time() # Calculate the total time taken and print the result
                TOTAL = t1 - TO
                print(TOTAL)
                print(f"File '{filename}' sent to {recipient}")
                #progress_bar['value'] = 0
                #root.update_idletasks()
            except Exception as e:
                print(f"Error sending file to {recipient}: {e}")
            finally:
                TCP_send_socket.close()
    except Exception as e:
        print(f"Error opening file '{filename}': {e}")

# This is for setting up the GUI
# It makes the grid for Tkinter to work on
# It also has a splash screen that shows while the program is loading
# This class also handles the threads that communicate with the server and receives
# messages form server
# 
# each client has a upload and download function.If the file requested to download doesn't exist it requests the closest match
class ClientGUI:
    FILELIST = []
    FILE_IP = []
    def __init__(self, window):
        self.master = window
        window.title("Stellies Swap")  # Title of the GUI
        window.geometry("800x400")

        self.master.configure(bg='azure4')

        self.my_logo = ImageTk.PhotoImage(Image.open('image/logo.jpg'))
        my_label = Label(image=self.my_logo)
        my_label.pack()

        self.master.after(1200, self.hide_image)

        self.transfer_label = None
        self.tcp_button = None
        self.rbudp_button = None
        self.progress_bar = ttk.Progressbar(self.master, orient=HORIZONTAL, length=445, mode='determinate')
        self.progress_bar2 = ttk.Progressbar(self.master, orient=HORIZONTAL, length=445, mode='determinate')

# runs on own thread
    def server_comms(self):
        self.comms_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.comms_socket.connect((SERVER_HOST, SERVER_COMMS_PORT))

    def server_comms_send(self, message):
        message = message.encode()
        self.comms_socket.send(message)
    
    def server_comms_receive(self):

        def find_nth(haystack, needle, n):
            start = haystack.find(needle)
            while start >= 0 and n >= 1:
                start = haystack.find(needle, start+len(needle))
                n -= 1
            return start

        while True:
            message = self.comms_socket.recv(1024)
            textmessage = message.decode()

            print("\nserver sent: "+textmessage+"\n")
            
            if textmessage[0:3] == "add":
                start =find_nth(textmessage, ":", 0)
                end = find_nth(textmessage, ":", 1)
                filename = textmessage[start+1:end]
                ClientGUI.FILELIST.append(filename)
                
                # find the IP address:
                IpBegin = end+1
                IpEnd = len(textmessage)
                IPAddress = textmessage[IpBegin:IpEnd]
                ClientGUI.FILE_IP.append(IPAddress)

            # make socket and send file
            if textmessage[0:3] == "req":
                start = find_nth(textmessage, ":", 0)
                end = find_nth(textmessage, ":", 1)
                filename = textmessage[start+1:end]
                end = find_nth(textmessage, ":", 1)
                # find the IP address:
                IpBegin = end+1
                IpEnd = find_nth(textmessage, ":", 2)
                IPowner = textmessage[IpBegin:IpEnd]
                IPreq = textmessage[IpEnd+1: len(textmessage)]
                print(IPreq)
                print(IPowner)
                print("-----------")
                print(textmessage)
                if IPreq != IPowner and IPreq != THIS_CLIENT_IP:
                    send_file_thread = threading.Thread(target=lambda: TCP_send(self.progress_bar, IPreq, filename))
                    send_file_thread.start()
            
                # IPowner and IPreq is correct

                global FILENAMETEMP
                global FILENAME
                file_path =  os.path.abspath(filename)# Show the file selection dialog
                FILENAMETEMP = file_path
                FILENAME = file_path[file_path.rfind('/')+1:]
            # ask user to enter a new username
            if textmessage[0:14] == "username taken":
                self.username_button.configure(state='normal')
                self.transfer_button.configure(state='disable')
                self.tcp_button.configure(state='disabled')
                print("username is taken\nTry anothe one")


# this function removes the splash screen afte loading
    def hide_image(self):
        for widget in self.master.winfo_children(): # Remove the label containing the image
            if isinstance(widget, Label):
                widget.destroy()

        self.transfer_button = Button(text="Search", command=self.search, width=15, height=1, font=("Arial", 20), state='disabled') # Add the transfer button
        self.transfer_button.place(x=20, y=80)
       
        self.file_path_text = Text(self.master, width=55, height=1, state='normal') # Add the file path option box
        self.file_path_text.place(x=300, y=87)

        self.username_text = Text(self.master, width=35, height=1, state='normal')
        self.username_text.place(x=300, y=25)

        self.username_button = Button(text="Confirm Username", command=self.username_handler, width=15, height=1, font=("Arial", 10))
        self.username_button.place(x=20, y=25)
        
        self.transfer_label = Label(self.master, text="PROGRESS:", font=("Arial, 20"), bg='azure4') # Add Receive text
        self.transfer_label.place(x=20, y=195)
        
        self.transfer_label = Label(self.master, text="Transfer type: TCP", font=("Arial, 10"), bg='azure4') # Add the text below progress bar
        self.transfer_label.place(x=100, y=240)
        
        self.tcp_button = Button(text="Upload", command=self.transfer, width=15, height=1, font=("Arial", 20), state='disabled') # Add the transfer button
        self.tcp_button.place(x=20, y=135)

        self.progress_bar = ttk.Progressbar(self.master, orient=HORIZONTAL, length=445, mode='determinate') # Add the progress bar receive
        self.progress_bar.place(x=300, y=240)
# handles the usernames and ensures they are unique
    def username_handler(self):
        temp_username = self.username_text.get(1.0, "end-1c")
        temp_username = "tmp" + temp_username
        self.username_button.configure(state='disabled')
        self.transfer_button.configure(state='normal')
        self.tcp_button.configure(state='normal')
        request_username_thread = threading.Thread(target=lambda: self.server_comms_send(temp_username))
        request_username_thread.start()

    # searches for a file on the local availible files list and then requests it for download
    def search(self):

        # this function returns the closest match to a word in a wordlist
        def closeMatches(fileList, word): 
            matches  = get_close_matches(word,fileList)
            if matches:
                return matches[0]    
            else: 
                return -1

        i = 0
        owner = ""
        exits = False
        print(self.FILELIST)
        print(self.FILE_IP)

        send_file = self.file_path_text.get(1.0, "end-1c")

        for files in self.FILELIST:
            if send_file == files:
                owner = self.FILE_IP[i]
                exits = True
            i+=1
        
        if not exits:
            i = 0
            close_match = closeMatches(self.FILELIST, send_file)
            if close_match != -1:

                for files in self.FILELIST:
                    if close_match == files:
                        owner = self.FILE_IP[i]

                    i+=1

                print("close_match: "+ close_match)
                send_file = close_match
            else:
                print("File does not exist")
                return
        
        message = "req:" + send_file+ ":" + owner + ":" + THIS_CLIENT_IP
        send_req_thread = threading.Thread(target=lambda: self.server_comms_send(message))
        send_req_thread.start()
        pass

    def create_time(self):
        self.transfer_label = Label(self.master, text=TOTAL , font=("Arial, 10"), bg='CadetBlue1')
        self.transfer_label.place(x=80, y=280)

    # tells the server to make the specified file availible for download and tell all other clients
    def transfer(self):

        message = "add:"+self.file_path_text.get(1.0, "end-1c")
        if message[0:3] == "add":
            message = message +":"+THIS_CLIENT_IP
            print("add message: "+message)
        

        self.progress_bar['value'] = 0
        send_comm_thread = threading.Thread(target=lambda: self.server_comms_send(message))
        send_comm_thread.start()

    # these 2 functions handle the progressbars for updating them while the transfers are ongoing
    def get_progress_bars(self):
        return self.progress_bar, self.progress_bar2

    def update_progress(self, value):
        self.progress_bar['value'] = value
        self.master.update_idletasks()


# Main to start the program    
def main():
    global root
    root = tk.Tk()
    app = ClientGUI(root)
    app.server_comms()
    # communication with server and receiving from peer is handled on 
    # diffirent threads
    comms_receive_thread = threading.Thread(target=lambda: app.server_comms_receive())
    comms_receive_thread.start()
    progress_bar, progress_bar2 = app.get_progress_bars()
    receive_thread = threading.Thread(target=lambda: TCP_receive(progress_bar, app.update_progress))
    receive_thread.start()

    root.mainloop()

if __name__ == '__main__':
    main()

