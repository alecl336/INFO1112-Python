import os
import socket
import sys
import re
import time
import datetime
import secrets
import base64
import hmac


# Removed for privacy reasons
PERSONAL_ID = ''
PERSONAL_SECRET = ''


def main():
    # TODO
    #Test to see if config file is provided.
    try:
        config_file = sys.argv[1]
    except:
        exit(1)
    
    #Read config file and return port number
    try:
        port = config_reader(sys.argv[1], "server_port")
    except:
        exit(2)
    host = 'localhost'
    
    #Create socket
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    #Try binding program to given port.
    try:
        s.bind((host, port))
    except:
        exit(2)

    try:
        inbox_path = config_reader(sys.argv[1], "inbox_path")
        inbox_path = abs_path(inbox_path)
    except:
        exit(2)

    while True:
        s.listen(2)

        #booleans used to check 503
        ehlo_check = False
        from_check = False
        rcpt_check = False
        data_check = False
        auth_process_check = False
        auth_success = False
        

        #Used to check if email has been authenticated
        auth_email = False


        curr_challenge = ''

        #Used to store lines
        current_writer_f = []

        #Accept connection
        conn, addr = s.accept()

        conn.send(("220 Service ready\r\n").encode())
        print("S: 220 Service ready\r", flush=True)

        #Loop continuously - client send data, server receive. Server sends message, client receives data.
        while True:
            server_in = conn.recv(1024).decode()
            server_in = (server_in.lstrip("\r\n")).rstrip("\r\n")
            print("C: " + server_in + "\r", flush=True)

            #When client disconnects unexpectedly, it should send nothing to the server.
            if (server_in == ""):
                print("S: Connection lost\r", flush=True)
                break
            
            if (server_in.split()[0] == "EHLO"):
                if (ehlo_syntax_checker(server_in) == False):
                    err_501(conn)
                else:
                    msg = "250 127.0.0.1"
                    print("S: " + msg + "\r\nS: 250 AUTH CRAM-MD5\r", flush=True)
                    conn.send((msg + "\r\n250 AUTH CRAM-MD5\r\n").encode())
                    ehlo_check = True
            
            if (server_in.split()[0] == "SIGINT"):
                print("S: SIGINT received, closing\r", flush=True)
                conn.close()
                s.close()
                exit(0)
            
            #Challenge response from client.
            elif (auth_process_check == True):
                if (server_in == "*"):
                    err_501(conn)
                try:
                    return_msg = base64.b64decode(server_in)
                except:
                    err_501(conn)
                return_msg = return_msg.split()[1]
                p_secret = (PERSONAL_SECRET).encode('ascii')
                serv_digest_obj = hmac.new(p_secret, curr_challenge, digestmod="md5")
                serv_digest = serv_digest_obj.hexdigest()
                client_digest = return_msg.decode('ascii')

                #Compare digests
                if (hmac.compare_digest(serv_digest, client_digest)):
                    msg_235(conn)
                    auth_success = True
                    auth_email = True
                else:
                    err_535(conn)
                
                auth_process_check = False

            #Normal send back response.
            elif (server_in.split()[0] == "NOOP"):
                #In the case where NOOP is in the data of the email.
                if (rcpt_check == True and data_check == True):
                    msg_354(conn)
                else:
                    if (noop_syntax_checker(server_in)):
                        msg_250(conn)
                    else:
                        err_501(conn)
            
            #Then append information to the log file.
            #In the case where client info is "QUIT", send 221 reply then close connection.
            elif (server_in.split()[0] == "QUIT"):
                if (quit_syntax_checker(server_in)):
                    msg = "221 Service closing transmission channel"
                    print("S: " + msg + "\r", flush=True)
                    conn.send((msg + "\r\n").encode())
                    conn.close()
                    break
                else:
                    err_501(conn)
            
            #Authentication case
            elif (server_in.split()[0] == "AUTH"):
                if (auth_syntax_checker(server_in) == False):
                    err_504(conn)
                if (auth_success == False or from_check == True):
                    #Server sends challenge encoded message.
                    challenge = secrets.token_hex(16)
                    challenge = challenge.encode('ascii')
                    curr_challenge = challenge
                    challenge = base64.b64encode(challenge)
                    msg = b'334 ' + challenge + b'\r\n'
                    conn.send(msg)
                    print("S: 334 " + challenge.decode(), flush=True)
                    auth_process_check = True
                #Sends when auth already successed in same session, or server currently receiving mail.
                else:
                    err_503(conn)

            #RSET Case
            elif (server_in.split()[0] == "RSET"):
                #In the case where RSET is in the data of the email.
                if (rcpt_check == True and data_check == True):
                    msg_354(conn)
                else:
                    if (rset_syntax_checker(server_in)):
                        msg_250(conn)
                        current_writer_f.clear()
                        from_check = False
                        rcpt_check = False
                        data_check = False
                    else:
                        err_501(conn)

            #Start of sending email
            elif ("MAIL" in server_in):
                if (ehlo_check == True and from_check == False):
                    if (mail_syntax_checker(server_in, "MAIL FROM:<")):
                        msg = server_in.lstrip("MAIL FROM:")
                        msg = "From: " + msg
                        current_writer_f.append(msg + "\n")
                        msg_250(conn)
                        from_check = True
                    else:
                        err_501(conn)
                else:
                    err_503(conn)
            
            #Contains email recipients.
            elif ("RCPT" in server_in):
                if (from_check == True):
                    if (mail_syntax_checker(server_in, "RCPT TO:<")):
                        msg = server_in.lstrip("RCPT TO:")
                        msg = "To: " + msg
                        current_writer_f.append(msg + "\n")
                        rcpt_check = True
                        msg_250(conn)
                    else:
                        err_501(conn)
                else:
                    err_503(conn)

            #Highlights start of the content of the email.
            elif (server_in == "DATA"):
                if (rcpt_check == True and data_check == False):
                    msg_354(conn)
                    data_check = True
                else:
                    err_503(conn)
            
            #Content of email
            elif(data_check == True and server_in != "."):
                current_writer_f.append(server_in + "\n")
                msg_354(conn)
            
            #Reached end of email
            elif (server_in == "."):
                msg_250(conn)
                data_check = False
                #Check if email has been authenticated
                if (auth_email == False):
                    mail_writer(current_writer_f, inbox_path)
                else:
                    mail_writer(current_writer_f, "auth." + inbox_path)


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

        if (line[0] == "inbox_path" and item == "inbox_path"):
            path = line[1].strip("\n")
            item_inside = True
            return(path)

        if (line[0] == "server_port" and item == "server_port"):
            port_no = int(line[1].strip("\n"))
            item_inside = True
            return(port_no)
    
    if (item_inside == False):
        exit(2)


# 501 error Message sender
def err_501(conn):
    print("S: 501 Syntax error in parameters or arguments\r", flush=True)
    conn.send("501 Syntax error in parameters or arguments\r\n".encode())


# 250 Message sender
def msg_250(conn):
    msg = "250 Requested mail action okay completed"
    print("S: " + msg + "\r", flush=True)
    conn.send((msg + "\r\n").encode())

# 354 Message sender
def msg_354(conn):
    msg = "354 Start mail input end <CRLF>.<CRLF>"
    print("S: " + msg + "\r", flush=True)
    conn.send((msg + "\r\n").encode())


# 503 error Message sender
def err_503(conn):
    msg = "503 Bad sequence of commands"
    print("S: " + msg + "\r", flush=True)
    conn.send((msg + "\r\n").encode())

# 504 error Message sender
def err_504(conn):
    msg = "504 Unrecognized authentication type"
    print("S: " + msg + "\r", flush=True)
    conn.send((msg + "\r\n").encode())

# 235 Message sender
def msg_235(conn):
    msg = "235 Authentication successful"
    conn.send((msg + "\r\n").encode())
    print("S: " + msg + "\r", flush=True)



# 535 error Message sender
def err_535(conn):
    msg = "535 Authentication credentials invalid"
    print("S: " + msg + "\r", flush=True)
    conn.send((msg + "\r\n").encode())


def abs_path(path_name):
    if (path_name[0] == "~"):
        path_name = path_name[2:]
    final_path_name = os.path.abspath(path_name)
    return(final_path_name)


#Check MAIL command syntax
def mail_syntax_checker(command, str_check):
    if str_check not in command:
        return(False)
    command = command.split(":")
    mailbox = command[1]
    if (mailbox[0] != "<" or mailbox[-1] != ">"):
        return(False)
    mailbox = (mailbox.lstrip("<")).rstrip(">")
    if (len(mailbox) <= 1):
        return(False)
    domain = (mailbox.split("@"))[1]
    dot_string = (mailbox.split("@"))[0]

    if ("." not in domain):
        return(False)

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


#Check EHLO command syntax
def ehlo_syntax_checker(command):
    if (len(command.split()) != 2):
        return(False)
    address = command.split()[1]
    if (ip_valid(address) == False):
        return(False)
    return(True)


#Check QUIT command syntax
def quit_syntax_checker(server_in):
    ls_char = list(server_in)
    if (len(ls_char) != 4):
        return(False)
    else:
        return(True)

#Check RSET command syntax
def rset_syntax_checker(server_in):
    ls_char = list(server_in)
    if (len(ls_char) != 4):
        return(False)
    else:
        return(True)

#Check NOOP command syntax
def noop_syntax_checker(server_in):
    ls_char = list(server_in)
    if (len(ls_char) != 4):
        return(False)
    else:
        return(True)

def auth_syntax_checker(server_in):
    if(len(server_in.split()) != 2):
        return(False)
    server_in = server_in.split()[1]
    if (server_in != "CRAM-MD5"):
        return(False)
    return(True)


#IP Address validity checker
def ip_valid(ip_ad):
    num_ls = ip_ad.split(".")
    if (len(num_ls) != 4):
        return(False)
    for num in num_ls:
        try:
            num = int(num)
        except:
            return(False)
        if (num > 255 or num < 0):
            return(False)
    return(True)


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


#Given date time converted to Unix datetime for file name purposes
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


if __name__ == '__main__':
    main()
