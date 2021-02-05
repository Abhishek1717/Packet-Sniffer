import socket
import time
import sys
import csv
import struct

class packet_snifer:
    
    def __init__(self):
        try:
            
            self.sock =socket.socket(socket.AF_PACKET , socket.SOCK_RAW, socket.ntohs(0x0003))
            self.filename="sniffer_agadire.csv"
            self.categories={'ip':0,'tcp':0,'udp':0,'dns':0,'icmp':0,'http':0,'https':0,'quic':0}
            
        except socket.error as msg:
            print("socket error cannot connect", msg)
            sys.exit()
            
           
    def count_packets(self):
        start=time.time()
        
        while time.time()-start<30:

            data=self.sock.recvfrom(65535)
            first_raw=struct.unpack('! 6s 6s H', data[0][:14])
            protocol=socket.htons(first_raw[2])
            
            if protocol==8:
                self.categories['ip']+=1
                ip=struct.unpack('!BBHHHBBH4s4s',data[0][14:34])
                   
                if ip[6]==1:
                    self.categories['icmp']+=1
                elif ip[6]==6:
                    self.categories['tcp']+=1
                    tcp=struct.unpack('!HHLLH',data[0][34:48])
                    
                    if tcp[0] ==80 or tcp[1]==80:
                        self.categories['http']+=1
                    elif tcp[0] ==53 or tcp[1]==53:
                         self.categories['dns']+=1   
                    if tcp[0] ==443 or tcp[1]==443:
                        self.categories['https']+=1
                    
                elif ip[6]==17:
                    self.categories['udp']+=1
                    udp=struct.unpack('!HHHH',data[0][34:42])
                    
                    if udp[0] ==53 or udp[1]==53:
                        self.categories['dns']+=1
                    elif udp[0] ==80 or udp[1]==80 or udp[0]==443 or udp[1]==443:
                        self.categories['quic']+=1
    
        self.write_to_file() 
        print("Exiting application after 30 seconds....")    
        self.close()
            
            
            
            
            
        
    def write_to_file(self):
        with open(self.filename,'w') as fp:
            write=csv.writer(fp)
            write.writerow(['protocol','count'])
            write.writerow(['ip',str(self.categories["ip"])])
            x="tcp,"+str(self.categories["tcp"])
            write.writerow(['tcp',str(self.categories["tcp"])])
            x="udp,"+str(self.categories["udp"])
            write.writerow(['udp',str(self.categories["udp"])])
            x="dns,"+str(self.categories["dns"])
            write.writerow(['dns',str(self.categories["dns"])])
            x="icmp,"+str(self.categories["icmp"])
            write.writerow(['icmp',str(self.categories["icmp"])])
            x="http,"+str(self.categories["http"])
            write.writerow(['http',str(self.categories["http"])])
            x="https,"+str(self.categories["https"])
            write.writerow(['https',str(self.categories["https"])])
            x="quic,"+str(self.categories["quic"])
            write.writerow(['quic',str(self.categories["quic"])])
            
            
        
        
        
        
        
    def close(self):
        self.sock.close()   
        
obj = packet_snifer()
obj.count_packets()
obj.close()
