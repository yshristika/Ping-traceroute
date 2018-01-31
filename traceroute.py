"""
Shristika Yadav
Computer networks
Project 3
Ping Trace-route
Implement in terminal - sudo python ./traceroute.py
"""
import socket
import struct
import sys
import os
import time
import select


port = 33434

def sTrace(dest_addr,n,probe,sumry):
    """
    main method for traceroute.
    :param dest_addr: destination address
    :param n: check whether to Print hop addresses numerically or not.
    :param probe: no of probes to send. default = 3
    :param sumry:to show the sumaary of packet lost or not.
    :return:
    """
    ttl = 1
    packetSize = 56
    while True:
        try:
            socketCurr = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
            socketCurr.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        except socket.error:
            etype, evalue, etraceback = sys.exc_info()
            print "socket error ", evalue
            print "ICMP message can only be sent from process running as root."
            sys.exit(1)
        packet_ID = getPacketID()
        packet = createPacket(packet_ID,packetSize)
        print ttl
        tries = probe
        probeAns = 0
        probeNAns = 0
        while tries>0:
            sentTime = pingSent(socketCurr, packet, dest_addr)
            tries = tries -1
            if sentTime == None:
                socketCurr.close()

            hop_addr, hop_name,traceTime = rTrace(socketCurr)
            if hop_addr != None:
                probeAns +=1
                if n == True:
                    print hop_addr, round((traceTime - sentTime) * 1000, 4), "ms"
                else:
                    print hop_addr, "(", hop_name, ")", round((traceTime - sentTime) * 1000, 4), "ms"
            else:
                probeNAns +=1
                print '*'
        if sumry == True:
            print probeAns, " probe answered"
            print probeNAns, " probe not answered"
        if hop_addr == socket.gethostbyname(dest_addr) or ttl > 30:
            break
        ttl += 1
        pass

def rTrace(socketCurr):
    """
    receive data from destination.
    :param socketCurr: socket
    :return: hop address, hop name, time packet received
    """
    timeout = struct.pack("ll", 5, 0)
    socketCurr.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)
    try:
        packet_data, addr = socketCurr.recvfrom(1024)
        traceTime = time.time()
        hop_addr = addr[0]
        try:
            hop_name = socket.gethostbyaddr(addr[0])[0]
        except socket.error:
            hop_name = addr[0]
        return hop_addr,hop_name,traceTime
    except socket.error:
        return None, None,None

def sendPing(dest_addr,timeout,packet_size):
    """
    main method for ping
    :param dest_addr: destination address
    :param timeout: Specify a timeout, in seconds, before ping exits regardless of how many packets have been received. default = 2
    :param packet_size: Specify the number of data bytes to be sent. The default is 56.
    :return: delay time
    """
    delay = None
    socketCurr = createSocket()
    packet_ID = getPacketID()
    packet = createPacket(packet_ID,packet_size)
    sentTime = pingSent(socketCurr,packet,dest_addr)

    if sentTime == None:
        socketCurr.close()
        return delay
    delay = receivePing(socketCurr, packet_ID, time.time(), timeout)

    return delay
    pass

def receivePing(socketCurr, packet_ID, pingTime, timeout):
    """
    Receives ack from the receiver.
    """
    left_time = timeout
    while True:
        ready = select.select([socketCurr], [], [], left_time)
        if ready[0] == []:
            return None
        startTime = time.time()
        packet_data, addr = socketCurr.recvfrom(1024)
        icmp_header = packet_data[20:28]
        type, code, checksum, p_id, sequence = struct.unpack('bbHHh', icmp_header)
        if p_id == packet_ID:
            return startTime - pingTime
        left_time = left_time - (startTime - pingTime)
        if left_time <= 0:
            return None

def pingSent(socketCurr,packet,dest_addr):
    """
    Sends ping to the destination.
    :param socketCurr: Socket
    :param packet: Packet going to send
    :param dest_addr: destination address which will be pinged
    :return: Time at which pakcet sent
    """
    sendTime = time.time()
    try:
        sent = socketCurr.sendto(packet,(dest_addr,port))
    except socket.error as e:
        print "Failure -" ,e.args[1]
        socketCurr.close()
        sendTime = None
    return sendTime

def checkSum(data):
    """
    calculates checksum. Its a 16-bit one's complement of the one's complement sum of the ICMP message.
    :param data: data for creating checksum
    :return: checksum calculated
    """
    sum = 0
    for idx in range(0,len(data),2):
        sum += ord(data[idx+1]) * 256 + ord(data[idx])
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer
    pass

def createPacket(packetID,packet_size):
    """
    Creates packet depending upon the packet size given
    :param packetID: packet id
    :param packet_size: packet size
    :return:
    """
    icmp_echoReq = 8
    header = struct.pack('bbHHh', icmp_echoReq, 0, 0, packetID, 1)
    data = (packet_size - 8) * "A"
    check_Sum = checkSum(header + data)
    header = struct.pack('bbHHh', icmp_echoReq, 0,
                         socket.htons(check_Sum), packetID, 1)
    return header + data
    pass

def getPacketID():
    """
    get packet id
    :return:
    """
    packet_ID = os.getpid() & 0xffff
    return packet_ID

def createSocket():
    """
    Creates socket
    :return:
    """
    try:
        socketCurr = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.getprotobyname("icmp"))
    except socket.error:
        etype, evalue, etraceback = sys.exc_info()
        print "socket error ", evalue
        print "ICMP message can only be sent from process running as root."
        sys.exit(1)
    return socketCurr

def ping(count,wait,packetSize,timeout,dest_addr):
    """
    Method for ping which calls all the send and receive methods.
    :param count: Stop after sending (and receiving) count ECHO_RESPONSE packets. If this option is not specified, ping will operate until interrupted.
    :param wait: Wait wait seconds between sending each packet. The default is to wait for one second between each packet.
    :param packetSize: Specify the number of data bytes to be sent. The default is 56, which translates into 64 ICMP data bytes when combined with the 8 bytes of ICMP header data.
    :param timeout: Specify a timeout, in seconds, before ping exits regardless of how many packets have been received.
    :param dest_addr: destination address
    :return:
    """
    try:
        print "PING ", dest_addr, "(", socket.gethostbyname(dest_addr), "): ", packetSize, " data bytes"
        for i in range(count):
            timeReceive = sendPing(dest_addr, timeout, packetSize)

            if timeReceive == None:
                print 'Request timeout for icmp_seq=', i
            else:
                timeReceive = round(timeReceive * 1000, 4)
                print packetSize + 8, "bytes from", socket.gethostbyname(
                    dest_addr), ": icmp_sequence=", i, "time=", timeReceive, "ms"
            time.sleep(wait)
    except socket.error:
        etype, evalue, etraceback = sys.exc_info()
        print "socket error ", evalue


def main():
    address = raw_input("Enter address ").split(" ")
    count = wait = packetSize = timeout = probe = 0
    numerc = False
    sumry = False
    for idx in range(1,len(address)):
        if(address[idx] == '-c'):
            count = int(address[idx+1])
            idx = idx+1
        if(address[idx] == '-i'):
            wait = int(address[idx+1])
            idx = idx + 1
        if address[idx] == '-s':
            packetSize = int(address[idx+1])
            idx = idx+1
        if address[idx] == '-t':
            timeout = int(address[idx + 1])
            idx = idx+1
        if address[idx] == '-n':
            numerc = True
        if address[idx] == '-q':
            probe = int(address[idx+1])
            idx = idx + 1
        if address[idx] == '-S':
            sumry = True
        if idx == len(address)-1:
            addr = address[idx]
            if address[0] == 'ping' or address[0] == 'Ping' or address[0] == 'PING':
                if count < 1:
                    count = 9999
                if wait < 1:
                    wait = 1
                if packetSize < 56:
                    packetSize = 56
                if timeout == 0:
                    timeout = 2
                ping(count, wait, packetSize, timeout, addr)
            else:
                if probe < 1:
                    probe = 3
                sTrace(addr,numerc,probe,sumry)


if __name__=='__main__':
    main()