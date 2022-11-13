from scapy.all import *

req = {}
def my_method(packet):
    global req
    if packet[0].haslayer(TCP):
        if packet[0].dport == 80:
            if packet[0].haslayer(Raw):
                r=packet[0][0][Raw].load
                if not packet[0].sport in req:
                    req[packet[0].sport] = {}
                req[packet[0].sport]["raw"] = r.splitlines()[0]
                req[packet[0].sport]["stime"] = float(packet.time)
        elif packet[0].sport == 80:
                if packet[0].haslayer(Raw):
                    if not packet[0].dport in req:
                        req[packet[0].dport] = {}
                    req[packet[0].dport]["dtime"] = float(packet.time)
                    req[packet[0].dport]["diff"] = req[packet[0].dport]["dtime"] - req[packet[0].dport]["stime"]



def main():
    res = ""
    global req
    sniff(offline='chall.pcap', prn=my_method,store=1)
    for r in req:
        res += str(r)+"\t"+str(req[r]["diff"])+"\t"+req[r]["raw"]+"\n"
    open("payload.txt","wb").write(res)

main()