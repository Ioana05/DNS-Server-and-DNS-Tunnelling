import socket
import base64
from scapy.all import *

server_ip = "198.7.0.2"
server_port = 53

def send_dns_request(query):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dns_request = DNS(
                      rd=1, 
                      qd=DNSQR(qname=query, qtype=16)
                    )
    client_socket.sendto(bytes(dns_request), (server_ip, server_port))
    print("Sent DNS request")
    response, _ = client_socket.recvfrom(65535)
    print("Received response from server")
    return DNS(response)

def send_ack(server_address, packet_id):
    ack_packet = DNS(
                    id=packet_id,
                    qr=1,
                    aa=0,
                    qdcount=0,
                    ancount=0,
                    nscount=0,
                    arcount=0
                    )
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.sendto(bytes(ack_packet), server_address)
    print("Sent ACK to server")

def start():
    file_name = "text"  # fisierul pe care vrem sa-l descarcam
   
    # cerere pentru a afla nr de chunks ale fisierului
    while True:
        response = send_dns_request(f"{file_name}.numchunks.example.local")
        if response.rcode == 3:
            print("File not found on server!")
            return
        if response.an:
            server_chunk_num = int(base64.b64decode(response.an.rdata[0]).decode())  # Extragem nr de chunks de la server
            print("Got server chunk number", server_chunk_num)
            send_ack((server_ip, server_port), response.id)
            break
        else:
            print("Chunk number packet lost. Retrying...")

    file_content = ""
    nr_p = 0 # nr de secventa pt pachete ca sa ne asiguram ca intreg fisierul este primit
    while True:
        response = send_dns_request(f"{file_name}.{nr_p}.example.local")
        if isinstance(response.an.rdata[0], bytes):
            file_chunk = base64.b64decode(response.an.rdata[0]).decode()
            # print(file_chunk)
            file_content += file_chunk
            nr_p += 1
            send_ack((server_ip, server_port), response.id)
            if nr_p == server_chunk_num:
                break
        else:
            print(f"Packet {nr_p} lost. Retrying...")

    with open("downloaded_file.txt", "w") as file:
        file.write(file_content)

start()
