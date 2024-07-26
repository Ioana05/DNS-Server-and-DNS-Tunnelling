from scapy.all import *
import base64
import socket
import hashlib

with open("text.txt", "r") as file:
    file_content = file.read()

dns_ips = {
    "text" : {
        "IP": "198.7.0.2",
        "NS_RECORD": "ns1.example.local.",
        "DATA": file_content 
    }
}
def chunk_file_content(file_content, length):
    return (file_content[0+i:length+i] for i in range(0, len(file_content), length))

simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto = socket.IPPROTO_UDP)
simple_udp.bind(('0.0.0.0', 53))
print("Server started. Waiting for connections...")

while True:
    request, address = simple_udp.recvfrom(65535)
    dns_request = DNS(request)
    dns = dns_request.getlayer(DNS)
    print(f"Received DNS request from {address}: ")
    print(dns_request.summary())
    print(dns_request.qd.qtype)
    if dns_request.qd.qtype == 16:  # TXT record
        print("TXT RECORD")
        file_name =  dns.qd.qname.decode("utf-8").split('.')[0]  # extragem numele fisierului din numele domeniului
        if file_name in dns_ips:                                 # verificam daca fisierul exista pe server
            file_content = dns_ips[file_name]["DATA"]            # luam continutul fisierului
            encoded_chunks = []                                  # codificam bucatile de date de bytes in Base64 (case sensitive)
            for chunk in chunk_file_content(file_content, 50):   # raspunsurile DNS limitate la 512 octeti, luam in calcul encodarea si overheadul protocolului, aici am pus 50 pt test cu un fisier mai mic
                encoded_chunks.append(base64.b64encode(chunk.encode()).decode())
            
            is_chunk_num_request = dns.qd.qname.decode("utf-8").split('.')[1] == "numchunks" # verificam daca e cerere pt nr de chunks ale fisierului
            if is_chunk_num_request:
                encoded_num_chunks = base64.b64encode(str(len(encoded_chunks)).encode()).decode()
                # ii comunicam clientului nr de chunks pe care trebuie sa le primeasca si asteptam ack
                chunks_num_response = DNS(
                    id=dns_request.id, # setam acelasi ID pt pachetul DNS ca incoming request 
                    qr=1,  # bitul QR setat la 1 sa indicam ca e response
                    aa=0,  # bitul pt authoritative answer nu e setat
                    rcode=0, # codul raspunsului setat fara erori
                    qd=dns_request.qd, # questionul original de la query-ul clientului
                    an=DNSRR( # obiect reply
                        rrname=dns_request.qd.qname, # numele RR setat la numele intrebarii din request
                        ttl=60,      # time to live al raspunsului
                        type="TXT",  # tipul pt RR
                        rclass="IN", # clasa pt RR setata la Internet
                        rdata=encoded_num_chunks
                    )
                )
                while True:
                    simple_udp.sendto(bytes(chunks_num_response), address)
                    try:
                        simple_udp.settimeout(5)  
                        ack, _ = simple_udp.recvfrom(1024)
                        ack_dns = DNS(ack)
                        if ack_dns.id == dns_request.id:
                            print("ACK received for chunk number")
                            break  
                    except socket.timeout:
                        print("Timeout! Resending chunk number...")
                
                simple_udp.settimeout(None) 
            else:
                nr_p = int(dns.qd.qname.decode("utf-8").split('.')[1])
                # construim raspunsul DNS pentru bucata de date cu indexul cerut si il trimitem cu stop-and-wait
                dns_response = DNS(
                    id = dns_request.id,
                    qr = 1,  
                    aa = 0,
                    rcode = 0,
                    qd = dns_request.qd,
                    an = DNSRR(
                                rrname=dns.qd.qname,
                                ttl=60,  
                                type="TXT",
                                rclass="IN",
                                rdata=encoded_chunks[nr_p]
                                )
                )
                simple_udp.sendto(bytes(dns_response), address) # trimitem pachetul

                while True: # asteptam confirmarea ack de la client pentru pachetul curent
                    try:
                        simple_udp.settimeout(5)  # timeout 5 secunde (sa nu asteptam la infinit)
                        ack, _ = simple_udp.recvfrom(1024)
                        ack_dns = DNS(ack)
                        if ack_dns.id == dns_request.id:
                            print("ACK received for sequence number:", nr_p)
                            break  
                    except socket.timeout:
                        print("Timeout! Resending packet...")
                        simple_udp.sendto(bytes(dns_response), address) # daca timeout expira si nu am primit ack de la client, retrimitem pachetul

                simple_udp.settimeout(None)  # resetam timeoutul
                
        else: # fisierul nu exista pe server
            print(file_name)
            dns_response = DNS(
                id=dns_request.id,
                qr=1,  
                aa=0,
                rcode=3,  # NXDOMAIN = non-existent domain 
                qd=dns_request.qd
            )
            simple_udp.sendto(bytes(dns_response), address)

