# Meysam H
# paf_final // PA_F.py


from socket import *
import thread
import sys
import md5
import hashlib

# when the server does not support the facility required.
def print501Error():
    gen = '501 Not execute\r\n\r\n'
    gen = gen + 'The server does not support it\r\n'
    gen = gen + 'Response from server when the server does\r\n'
    gen = gen + 'It is not supporting the request'
    gen = gen + 'it is for any resources.\r\n\r\n'
    return gen


# 400 bad request
def print400Error():
    gen = '400 Bad Request\r\n\r\n'
    gen = gen + 'Server Could not understand your request\r\n'
    gen = gen + 'repeat the request without r\n'
    gen = gen + 'adjustment. \r\n\r\n'
    return gen


# Malware Detected
def malwarehtmlMsg():
    htmlMsg = '<!DOCTYPE html>\n'
    htmlMsg = htmlMsg + '<html>\n'
    htmlMsg = htmlMsg + '<head>\n'
    htmlMsg = htmlMsg + '<title>Request Error</title>\n'
    htmlMsg = htmlMsg + '</head>\n'
    htmlMsg = htmlMsg + '<body>\n\n'
    htmlMsg = htmlMsg + '<h1>Page Blocked</h1>\n'
    htmlMsg = htmlMsg + '<p>** MALWARE DETECTED AND BLOCKED **</p>\n\n'
    htmlMsg = htmlMsg + '</body>\n'
    htmlMsg = htmlMsg + '</html>\n\n'
    return htmlMsg


#callback method for checking request, error checking, Forwarding to server,
# checking the return Msg, checking the malware
def newClientok(connSocket, addr):
    msg4Server = 'poop'
    sendMsgOk = False;
    sendPort = 80
    sndAddr = ""
    GET = 'GET '
    Host = 'Host: '
    ConnLine = 'Connection: close\r\n'
    errorMsg = ''
    #begining of parsing
    sen = connSocket.recv(1024)
    wrd = sen.split()
    #start message with GET also parse the Msg
    try:
        if wrd[0] == 'GET':
            #Finding the correct path and using the corrent Host and GET
            if wrd[1].startswith('/'):
                GET = GET + wrd[1] + ' ' + 'HTTP/1.0' + '\r\n'
                sen = connSocket.recv(1024)
                nextwrd = sen.split()
                if nextwrd[0] == 'Host:':
                    #catching the correct port from server for client
                    splitPrt = nextwrd[1].split(':')
                    if len(splitPrt) != 1:
                        sendPort = int(splitPrt[1])
                        nextwrd[1] = splitPrt[0]
                    Host = Host + nextwrd[1] + '\r\n'
                    sndAddr = nextwrd[1]
                    sendMsgOk = True;
                else:
                    errorMsg = print400Error()
                    connSocket.send(errorMsg)
                    connSocket.close()
            #receiving message as a URL
            else:
                splitAbs = wrd[1].split('/')
                if splitAbs[0] == 'http:' or splitAbs[0] == 'https:':
                    splitAbs.remove(splitAbs[0])
                    splitAbs.remove(splitAbs[0])
                splitPrt = splitAbs[0].split(':')
                if len(splitPrt) != 1:
                    sendPort = int(splitPrt[1])
                    splitAbs[0] = splitPrt[0]
                Host = Host + splitAbs[0] + '\r\n'
                sndAddr = splitAbs[0]
                splitAbs.remove(splitAbs[0])
                if len(splitAbs) > 0:
                    for c in splitAbs:
                        GET = GET + '/' + c
                else:
                    GET = GET + '/'
                GET = GET + ' ' + 'HTTP/1.0' + '\r\n'
                sendMsgOk = True;
            msg4Server = GET + Host + ConnLine + '\r\n'
        # printing message 501
        else:
            errorMsg = print501Error()
            connSocket.send(errorMsg)
            connSocket.close()
    except:
        #for FireFox accepting the blank request to the proxy
        print 'Experiencing Difficulties With FireFox'
    #parsing the message to the server
    if sendMsgOk == True:
        try:
            #connection between proxy and server
            clientSock = socket(AF_INET, SOCK_STREAM)
            clientSock.connect((sndAddr, sendPort))
            clientSock.send(msg4Server)
            dfServer = ''
            save4Client = ''
            #accepting information from server
            while 1:
                dfServer = clientSock.recv(1024)
                #in this case whether you get more information from server adding the message for the client
                if (len(dfServer) > 0):
                    save4Client += dfServer
                #checking the data for malware
                else:
                    # separating header
                    gBody = save4Client.split('\r\n\r\n')
                    #connectioning with team cymru
                    cymruSock = socket(AF_INET, SOCK_STREAM)
                    cymruSock.connect(('hash.cymru.com', 43))
                    messageToHash = gBody[1]
                    hshBody = hashlib.md5(messageToHash).hexdigest()
                    #printing the hash Body
                    hshBody.strip()
                    hshBody += "\r\n"
                    #send team cymru the hashed body
                    cymruSock.send(hshBody)
                    msgFCymru = ''
                    #getting message from cymru about queried web page
                    while 1:
                        dataFromCymru = cymruSock.recv(1024)
                        #reciving message from cymru
                        if (len(dataFromCymru) > 0):
                            msgFCymru += dataFromCymru
                        else:
                            chkCymruMsg = msgFCymru.split()
                            #checking last part of string if no data HTML pages don't have malware
                            if (chkCymruMsg[len(chkCymruMsg) - 1] == 'NO_DATA'):
                                connSocket.send(save4Client)
                                break
                            #checking message for client that contain malware
                            else:
                                appendToHTML = malwarehtmlMsg()
                                sendMalwareMessage = gBody[0] + '\r\n\r\n' + appendToHTML
                                print '** MALWARE DETECTED AND BLOCKED ** Hash: ' + hshBody
                                break
                    #disconnect the connectivite between proxy and cymru
                    cymruSock.close()
                    break
            #disconnect the connectivite between proxy and server
            clientSock.close()
            sendMsgOk = False;
        # catch the exceptions that happened
        except:
            sendMess = print400Error()
            connSocket.send(sendMess)
    #disconnect the connectivite between client and proxy
    connSocket.close()
    # sendPort = 80


# get the socket number if not use 3200
serverPort = 3200
if (len(sys.argv) > 1):
    serverPort = int(sys.argv[1].strip())
serverAddr = 'localhost'

try:
    serverSock = socket(AF_INET, SOCK_STREAM)
    print 'Got a socket with fd:', serverSock.fileno()

    serverSock.bind((serverAddr, serverPort))
    print 'Bound to:', serverSock.getsockname()

    serverSock.listen(1)

    # continue listening for clients for the proxy to accept
    while 1:
        print 'Looking for requests'
        connSocket, addr = serverSock.accept()
        print 'Received Connection From:', connSocket.getpeername(), ' fd: ', connSocket.fileno()

        # when a connection is made throw it into a new thread
        thread.start_new_thread(newClientok, (connSocket, addr))

        print "FINISHED"
except:
    print 'Typing Correct Port or Connect to your Localhost.'
    print 'Hint: python PA_F.py 3200'




