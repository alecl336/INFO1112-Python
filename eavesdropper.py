import os
import socket
import sys
import datetime
import time


def main():
    # TODO
    
    #One while true loop on the outside.
    #One on inside. The inside one is the actual processes of the client and server on repeat. 
    #The outside one is for when eavesdropper is trying to listen for commands. The inside one should only be broken on command "QUIT"

    #Config file done

    #try establish connection to client
    # while true loop, establish connection to server.
    #while true loop, receive and send. When quit command is called,


    try:
        config_file = sys.argv[1]
    except:
        exit(1)


    #Read config file and return port numbers
    c_port = config_reader(sys.argv[1], "client_port")
    s_port = config_reader(sys.argv[1], "server_port")
    host = 'localhost'

    #Create socket to act as server, to listen from client
    server_s = socket.socket()
    server_s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    #Try binding program to given port.
    try:
        server_s.bind((host, c_port))
    except:
        exit(2)

    try:
        spy_path = config_reader(sys.argv[1], "spy_path")
        spy_path = abs_path(spy_path)
    except:
        exit(2)

    while True:
        #listen again and again
        server_s.listen(2)
        conn, addr = server_s.accept()

        #Create socket to act as client, and connect to server
        client_s = socket.socket()
        try:
            client_s.connect((host, s_port))
        except:
            print("AS: Cannot establish connection", flush=True)
            exit(3)
        
        #Used to check if quit command was previously called.
        quit_called = False

        #Email storage and confirmation of start recording
        email_content = []
        start_record = False

        while True:
            #Processes.
            #Receives data from server. fs stands for "from server".
            data_fs = client_s.recv(1024).decode()
            fs = (data_fs.lstrip("\r\n")).rstrip("\r\n")

            #When server disconnects
            if(data_fs == ""):
                print("AS: Connection lost\r", flush=True)
                exit(3)
            
            #Multi line
            if (len(data_fs.split("\r\n")) > 2):
                data_lines = data_fs.split("\n")
                for line in data_lines:
                    if (line == ""):
                        continue
                    else:
                        print("S: " + line, flush=True)
            #Single line
            else:
                print("S: " + data_fs.strip("\n"), flush=True)

            #Send to client.
            conn.send(data_fs.encode())
            if (len(data_fs.split("\r\n")) > 2):
                data_lines = data_fs.split("\n")
                for line in data_lines:
                    if (line == ""):
                        continue
                    else:
                        print("AC: " + line, flush=True)
            else:
                print("AC: " + data_fs.strip("\n"), flush=True)
            
            #Check if quit was called, if yes, exit code 0.
            if (quit_called == True):
                exit(0)

            #Listen from client.
            data_fc = conn.recv(1024).decode()
            fc = (data_fc.lstrip("\r\n")).rstrip("\r\n")

            #When client disconnects.
            if(data_fc == ""):
                print("AC: Connection lost\r", flush=True)
                continue

            print("C: " + fc + "\r", flush=True)

            #Stop recording when start_record is false.
            if (fc == "."):
                start_record = False
                mail_writer(email_content, spy_path)

            #Record
            if (start_record == True and fc != "DATA"):
                if ("RCPT" in data_fc):
                    if (mail_syntax_checker(fc, "RCPT TO:<")):
                        msg = fc.lstrip("RCPT TO:")
                        msg = "To: " + msg
                        email_content.append(msg + "\n")
                else:
                    email_content.append(fc + "\n")

            #If MAIL is inside, start recording.
            if ("MAIL" in data_fc):
                if (mail_syntax_checker(fc, "MAIL FROM:<")):
                    msg = fc.lstrip("MAIL FROM:")
                    msg = "From: " + msg
                    email_content.append(msg + "\n")
                    start_record = True

            #Sends to server
            client_s.send(data_fc.encode())
            if (data_fc == "QUIT"):
                quit_called = True
            print("AS: " + fc + "\r", flush=True)


#Writes the mails to the given inbox_path location
def mail_writer(ls, inbox):
    #Loop through to find date (or file name)
    for line in ls:
        line_ls = line.split()
        if (line_ls[0] == "Date:"):
            date = (line.lstrip("Date: "))
            date = date.rstrip("\r\n")
    
    #Setting file name.
    if (date == ""):
        filename = "unknown.txt"
    else:
        filename = date_convert(date)
    
    final_destination = inbox + "/" + filename
    
    #Writing to the file.
    f = open(final_destination, "w")
    for line in ls:
        f.write(line)
    f.close()


def date_convert(date_given):
    #Check to see if given date is correctly formatted.
    try:
        datetime.datetime.strptime(date_given, "%a, %d %b %Y %H:%M:%S %z")
    except:
        return("unknown.txt")

    dates_ls = date_given.split()
    day = int(dates_ls[1])
    months_ls = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    month = int(months_ls.index(dates_ls[2])) + 1
    year = int(dates_ls[3])
    time_ls = (dates_ls[4]).split(":")
    hour = int(time_ls[0])
    minutes = int(time_ls[1])
    seconds = int(time_ls[2])
    time_offset = dates_ls[5]

    hour = int(hour)
    time_inter = datetime.datetime(year, month, day, hour, minutes, seconds)
    final_time = time.mktime(time_inter.timetuple())
    final_time = int(final_time)
    file_name = str(final_time) + ".txt"
    return(file_name)


#Check MAIL command syntax
def mail_syntax_checker(command, str_check):
    if str_check not in command:
        return(False)
    command = command.split(":")
    mailbox = command[1]
    if (mailbox[0] != "<" or mailbox[-1] != ">"):
        return(False)

    #Gets Source
    mailbox = (mailbox.lstrip("<")).rstrip(">")
    if (len(mailbox) <= 1):
        return(False)
    #Get domain and dot_String
    domain = (mailbox.split("@"))[1]
    dot_string = (mailbox.split("@"))[0]

    #Invalid domain
    if ("." not in domain):
        return(False)

    #Source cannot start with "-"
    if (dot_string[0] == "-"):
        return(False)
    
    if ("." in dot_string):
        par1 = dot_string.split(".")[0]
        par2 = dot_string.split(".")[1]
        if (par1[0] == "-" or par2[0] == "-"):
            return(False)
    
    if ("." in domain):
        par1 = domain.split(".")[0]
        par2 = domain.split(".")[1]
        if (par1[-1] == "-" or par1[0] == "-"):
            return(False)
        if (par2[-1] == "-" or par2[0] == "-"):
            return(False)
    return(True)


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

        if (line[0] == "spy_path" and item == "spy_path"):
            path = line[1].strip("\n")
            item_inside = True
            return(path)

        if (line[0] == "server_port" and item == "server_port"):
            port_no = int(line[1].strip("\n"))
            item_inside = True
            return(port_no)
        
        if (line[0] == "client_port" and item == "client_port"):
            port_no = int(line[1].strip("\n"))
            item_inside = True
            return(port_no)
    
    if (item_inside == False):
        exit(2)


#Converts to absolute path
def abs_path(path_name):
    if (path_name[0] == "~"):
        path_name = path_name[2:]
    final_path_name = os.path.abspath(path_name)
    return(final_path_name)


if __name__ == '__main__':
    main()
