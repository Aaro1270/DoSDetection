from datetime import datetime
import string
import binascii
import socket
import struct
import os

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)

IPMonitor = {}
timeStamp = {}
blockedIP = set()
blockedMAC = set()

logFile = open("DoSDetectionLogs",'a')

time = datetime.now()

logFile.writelines(str(time))
logFile.writelines("\n")

RequestLimit = 15

while True:
    pkt = s.recvfrom(2048)
    ipHeader = struct.unpack("!8sB3s4s4s", pkt[0][14:34])
    IP = socket.inet_ntoa(ipHeader[3])

    macHeader = struct.unpack("!6s6s2s", pkt[0][0:14])
    MAC = string.upper(binascii.hexlify(macHeader[1]))
    MAC = ':'.join(MAC[i:i+2] for i in range (0, len(MAC), 2))

    if((IP not in blockedIP) and (MAC not in blockedMAC)):
        log = ("[" + time.strftime('%H:%M:%S') + "]: The IP of the Current Packet is: " + IP + ", MAC Address: " + MAC)
        print(log)

        if(IPMonitor.has_key(IP)):
            IPMonitor[IP] = IPMonitor[IP] + 1
        else:
            IPMonitor[IP] = 1
            timeStamp = time

        if((IPMonitor[IP] >= RequestLimit) and ((time - timeStamp[IP]).seconds < 65)):
            log = ("["+ time.strftime('%H:%M:%S') + "]: DoS Attack Is Detected From: " + IP + " With MAC Address: " + MAC)
            print(log)
            logFile.writelines(log)

            os.system(str("sudo iptables-legacy -A INPUT -s " + (IP.replace('\'','')) + " -j DROP"))
            os.system(str("sudo iptables-legacy -A INPUT -m mac --mac-source  " + MAC + " -j DROP"))

            blockedIP.add(IP)
            blockedMAC.add(MAC)

            log = ("[" + time.strftime('%H:%M:%S') + "]: IP Address: " + IP + " & MAC Address: " + MAC + " Has Been Blacklisted")
            print(log)
            logFile.writelines(log)
            logFile.writelines("\n")
    
        if((time - timeStamp[IP]).seconds > 180):
            IPMonitor[IP] = 1

        timeStamp[IP] = time
    elif((MAC in blockedMAC) and (IP not in blockedIP)): # if blocked mac but different ip then block the ip as well
        os.system(str("sudo iptables-legacy -A INPUT -s " + (IP.replace('\'','')) + " -j DROP"))
        
        log = ("[" + time.strftime('%H:%M:%S') + "]: IP Address: " + IP + " & Blacklisted MAC Address: " + MAC + " Has Been Blacklisted")
        print(log)
        logFile.writelines(log)
    
    elif((MAC not in blockedMAC) and (IP in blockedIP)):
        os.system(str("sudo iptables-legacy -A INPUT -m mac --mac-source  " + MAC + " -j DROP")) 
        
        log = ("[" + time.strftime('%H:%M:%S') + "]: Blacklisted IP Address: " + IP + " & MAC Address: " + MAC + " Has Been Blacklisted")
        print(log)
        logFile.writelines(log)