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
    # Obtian the IP address by extracting it from the ucrrent packet

    macHeader = struct.unpack("!6s6s2s", pkt[0][0:14])
    MAC = string.upper(binascii.hexlify(macHeader[1]))
    MAC = ':'.join(MAC[i:i+2] for i in range (0, len(MAC), 2))
    # Obtain the MAC address form the current packet and format it so it can be used to block the address and to output in a standard format

    if((IP not in blockedIP) and (MAC not in blockedMAC)):
        # Check if either the IP or MAC address ahve already been blocked
        log = ("[" + time.strftime('%H:%M:%S') + "]: The IP of the Current Packet is: " + IP + ", MAC Address: " + MAC)
        print(log)
        # Output the current IP and MAC address along with the time

        if(IPMonitor.has_key(IP)):
            IPMonitor[IP] = IPMonitor[IP] + 1
            # Increment the counter if the IP has been seen before
        else:
            IPMonitor[IP] = 1
            timeStamp[IP] = time
            # If the IP has not been seen before then add it to the dictionary and mark the time for that IP

        if((IPMonitor[IP] >= RequestLimit) and ((time - timeStamp[IP]).seconds < 65)):
            # If the IP address has gone over the allowed number or requests within the 65 second timeframe 
            # then it fits the criteria for a DoS Attack 
            log = ("["+ time.strftime('%H:%M:%S') + "]: DoS Attack Is Detected From: " + IP + " With MAC Address: " + MAC)
            print(log)
            logFile.writelines(log)

            os.system(str("sudo iptables-legacy -A INPUT -s " + (IP.replace('\'','')) + " -j DROP"))
            # Block the IP address using iptables-legacy
            os.system(str("sudo iptables-legacy -A INPUT -m mac --mac-source  " + MAC + " -j DROP"))
            # Block the MAC Address using iptables-legacy
            
            blockedIP.add(IP)
            blockedMAC.add(MAC)
            # Add the IP and MAC to the blocked list  

            log = ("[" + time.strftime('%H:%M:%S') + "]: IP Address: " + IP + " & MAC Address: " + MAC + " Have Been Blacklisted")
            print(log)
            logFile.writelines(log)
            logFile.writelines("\n")
    
        if((time - timeStamp[IP]).seconds > 180):
            IPMonitor[IP] = 1
            # Reset the IP counter if they haven't made made a request in the past 3 minutes 

        timeStamp[IP] = time
        # Update timestamp

    elif((MAC in blockedMAC) and (IP not in blockedIP)):
        # If the request comes from a blocked MAC address with a new IP then block the new IP
        os.system(str("sudo iptables-legacy -A INPUT -s " + (IP.replace('\'','')) + " -j DROP"))
        blockedIP.add(IP)

        log = ("[" + time.strftime('%H:%M:%S') + "]: IP Address: " + IP + " & Blacklisted MAC Address: " + MAC + " Has Been Blacklisted")
        print(log)
        logFile.writelines(log)
    
    elif((MAC not in blockedMAC) and (IP in blockedIP)):
        # If the request comes form a blocked IP address with a new MAC address then block the new MAC
        os.system(str("sudo iptables-legacy -A INPUT -m mac --mac-source  " + MAC + " -j DROP")) 
        blockedMAC.add(MAC)

        log = ("[" + time.strftime('%H:%M:%S') + "]: Blacklisted IP Address: " + IP + " & MAC Address: " + MAC + " Has Been Blacklisted")
        print(log)
        logFile.writelines(log)