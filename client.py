import os
import socket
import sys
import secrets
import base64
import hmac


# Removed for privacy reasons
PERSONAL_ID = ''
PERSONAL_SECRET = ''


def main():
    
    # TODO
    #Reading from the config file.
    try:
        config_file = sys.argv[1]
    except:
        exit(1)
    
    client_s = socket.socket()
    #Read config file and return port number
    try:
        port = config_reader(sys.argv[1], "server_port")
        host = 'localhost'
        send_path = config_reader(sys.argv[1], "send_path")
    except:
        exit(2)
    
    #Read files from path, store in list. Combine path with file name.
    #Then loop through within a try except, and store information in dictionary. If at any point except is raised, exit.
    send_path = os.path.abspath(send_path)
    email_list = email_lister(send_path)

    for file in email_list:
        #Gets all data from the file.
        info = email_reader(send_path, file)

        filepath = send_path + "/" + file
        #Check for auth file
        auth = auth_check(filepath)

        #Checks for email parsing errors.
        mail_content_check(info, filepath)

        #email_sender(data)
        client_s = socket.socket()
        #Try connecting and send connection initialisation msg.
        try:
            client_s.connect((host, port))
        except:
            print("C: Cannot establish connection", flush=True)
            exit(3)

        counter = 0
        temp_counter = 0
        while True:
            data = client_s.recv(1024).decode()
            if (data == ""):
                #Start mail process.
                break

            #To separate between single line and multiline
            if (len(data.split("\r\n")) > 2):
                data_lines = data.split("\n")
                for line in data_lines:
                    if (line == ""):
                        continue
                    else:
                        print("S: " + line, flush=True)
            else:
                print("S: " + data.strip("\n"), flush=True)
            
            #Connection to server case.
            if ((data.split())[0] == "220"):
                msg = "EHLO 127.0.0.1"
                print("C: " + msg + "\r", flush=True)
                client_s.send((msg+"\r\n").encode())

            #Connection close case
            elif (data == "221"):
                client_s.close()
                break
            
            #Authentication case
            elif (data.split()[0] == "334"):
                p_secret = (PERSONAL_SECRET).encode('ascii')
                item = (data.split()[1])
                item = item.encode('ascii')
                serv_digest_obj = hmac.new(p_secret, item, digestmod="md5")
                answer = serv_digest_obj.hexdigest()
                answer = PERSONAL_ID + " " + answer
                print(answer, flush=True)
                client_s.send(base64.b64encode(answer))
                auth = False

            #Respond to server
            elif ((data.split())[0] == "250"):
                if (auth == True):
                    msg = "AUTH CRAM-MD5"
                    print("C: " + msg + "\r", flush=True)
                    client_s.send((msg + "\r\n").encode())
                    continue

                if (counter >= len(info)):
                    print("C: QUIT\r", flush=True)
                    client_s.send("QUIT\r\n".encode())
                    counter += 1
                #Initial case
                elif (counter == 0):
                    info[0] = (info[0].lstrip("From: "))
                    msg = "MAIL FROM:" + info[0].strip("\r\n")
                    print("C: " + msg.rstrip() + "\r", flush=True)
                    client_s.send((msg+"\r\n").encode())
                    counter += 1
                    # send from
                else:
                    #Send RCPT while counter is less than emails given.
                    #If more, send DATA
                    ls_emails = (info[1].lstrip("To: ")).split(",")
                    #Loop through email names.
                    if (temp_counter < len(ls_emails)):
                        msg = "RCPT TO:" + ls_emails[temp_counter].strip("\r\n")
                        print("C: " + msg+ "\r", flush=True)
                        client_s.send((msg+"\r\n").encode())
                        temp_counter += 1
                    
                    else:
                        print("C: DATA\r")
                        client_s.send("DATA\r\n".encode())
                        counter += 1

            elif ((data.split())[0] == "354"):
                if (counter >= len(info)):
                    print("C: .\r", flush=True)
                    client_s.send(".\r\n".encode())
                else:
                    msg = info[counter].strip("\r\n")
                    print("C: " + msg + "\r", flush=True)
                    client_s.send((msg+"\r\n").encode())
                    counter += 1


#Config file reader.
def config_reader(filepath, item):
    data = []
    try:
        f = open(filepath, "r")
        data = f.readlines()
    except:
        exit(2)

    item_inside = False
    for line in data:
        line = line.split("=")

        if (line[0] == "send_path" and item == "send_path"):
            path = line[1].strip("\n")
            item_inside = True
            return(path)

        if (line[0] == "server_port" and item == "server_port"):
            port_no = int(line[1].strip("\n"))
            item_inside = True
            return(port_no)
    
    if (item_inside == False):
        exit(2)

def email_lister(filepath):
    try:
        file_names = os.listdir(filepath)
        file_names.sort()
        return(file_names)
    #In the situation where send_path is unreadable
    except:
        exit(2)

def email_reader(filepath, file):
    file = filepath + "/" + file
    data = []
    #Start running through each file and parse the info.
    try:
        f = open(file, "r")
        data = f.readlines()
        f.close()
    except:
        print("C: " + file + ": Bad formation", flush=True)
    return(data)


#Checks mail content
def mail_content_check(data, filename):
    if ("From: " not in data[0]):
        print("C: " + filename + ": Bad formation", flush=True)
        exit(0)
    
    if ("To: " not in data[1]):
        print("C: " + filename + ": Bad formation", flush=True)
        exit(0)
    
    if ("Date: " not in data[2]):
        print("C: " + filename + ": Bad formation", flush=True)
        exit(0)
    
    if ("Subject: " not in data[3]):
        print("C: " + filename + ": Bad formation", flush=True)
        exit(0)

def auth_check(filename):
    files = filename.split("/")
    for file in files:
        if (file.lower() == "auth"):
            return(True)
    
    return(False)

if __name__ == '__main__':
    main()
