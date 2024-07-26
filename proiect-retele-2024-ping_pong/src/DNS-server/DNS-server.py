from scapy.all import *
import socket

dns_ips = {
    "example.local.": {
        "IP": "175.113.1.103",
        "NS_RECORD": "ns1.example.local."
    },
    "sub.example.local.": {
        "IP": "180.145.1.202",
        "NS_RECORD": "ns1.example.local."
    },
}

# prima data cand vom scrie o adresa in browser, aceasta va ajunge la un DNS resolver
# care va comunica apoi cu serverele. Vom realiza acest lucru prin crearea 
# unui socket care va folosi adrese IPv4(AF_INET) si va folosi protocolul UDP
simple_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto = socket.IPPROTO_UDP)

# acest socket va folosi portul 53, port standardizat pentru DNS Server
simple_udp.bind(('0.0.0.0', 53))

# urmatorul pas este sa procesam raspunsurile, iar pentru asta vom folosi un loop infinit
while True:
    # udp este un protocol care nu mentine o conexiune permanenta, de aceea va trebui sa tratam fiecare pachet independent
    # recvfrom va returna un tuplu care va contine request ul si adresa_requestului(adresa IP ului si portul de unde vine pachetul) 
    # 65535 este adresa maxima a bufferului pentru UDP
    request, adresa_requestului = simple_udp.recvfrom(65535)
    # ca sa nu lucram direct cu un sir de bytes, obtinem un obiect Scapy care contine straturile de protocol DNS ale
    # pachetului , incat sa fie mult mai usor de manipulat
    packet = DNS(request)
    # luam datele obtinute prin instructiunea anterioara
    dns = packet.getlayer(DNS)

    # OPCODE=0 corespunde unui query
    if dns is not None and dns.opcode == 0:
        print("Got next request: ")
        print(packet.summary())

        # retinem numele domeniului/ subdomeniului pe care il cautam
        name = dns.qd.qname.decode("utf-8")
        print(name)

        # vom trata cateva record type uri

        #request A
        if dns.qd.qtype == 1:
            print("e ok e pe A")
            if name in dns_ips:
                current_ip = dns_ips[name]["IP"]
                # un pachet DNS va contine Header, Question Section, Answer Section, Authority Section and Additional Section
                # il construim
                dns_answer = DNSRR(
                    rrname = dns.qd.name,
                    ttl = 3600, # cat timp ar trebui sa tinem minte in cache raspunsul DNS (noi setam 3600 s = 1h)
                    type = "A",
                    rclass = "IN", # IN = internet class, este cea mai utilizata
                    rdata = current_ip
                )
                dns_response = DNS(
                    id = packet[DNS].id, # trebuie sa avem acelasi id ca in request
                    qr = 1, # folosi1 pt raspuns si 0 pt query
                    aa = 0,
                    rcode = 0, # nicio eroare
                    qd = packet.qd, 
                    an = dns_answer)
            else:
                # cautam la serverul google
                forwarded_query = IP(dst='8.8.8.8') / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=dns.qd)
                # functia sr1 va trimite query ul si va astepta pentru un singur raspuns
                forwarded_response = sr1(forwarded_query, verbose=0)
                if forwarded_response and forwarded_response.haslayer(DNS):
                    forwarded_response[DNS].id = dns.id  # pastram id ul din request
                    dns_response = forwarded_response[DNS]
        # NS record
        elif dns.qd.qtype == 2:
            print("e ok pe B")
            if name in dns_ips:
                ns_record = dns_ips[name]["NS_RECORD"]
                dns_answer = DNSRR(
                    rrname = dns.qd.name,
                    ttl = 3600, # cat timp ar trebui sa tinem minte in cache raspunsul DNS (noi setam 3600 s = 1h)
                    type = "NS",
                    rclass = "IN", # IN = internet class, este cea mai utilizata
                    rdata = ns_record
                )
                dns_response = DNS(
                    id = packet[DNS].id, # trebuie sa avem acelasi id ca in request
                    qr = 1, # folosi1 pt raspuns si 0 pt query
                    aa = 0,
                    rcode = 0, # nicio eroare
                    qd = packet.qd, 
                    an = dns_answer)
            else:
                forwarded_query = IP(dst='8.8.8.8') / UDP(sport=RandShort(), dport=53) / DNS(rd=1, qd=dns.qd)
                forwarded_response = sr1(forwarded_query, verbose=0)
                if forwarded_response and forwarded_response.haslayer(DNS):
                    forwarded_response[DNS].id = dns.id  
                    dns_response = forwarded_response[DNS]
        
        simple_udp.sendto(bytes(dns_response), adresa_requestului)

simple_udp.close()




