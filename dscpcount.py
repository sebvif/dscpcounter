from scapy.all import *
import argparse

load_contrib('gtp')

parser=argparse.ArgumentParser()
parser.add_argument('filename')
parser.add_argument('reference') #se cuentan los paquetes con origen y destino de esta mac address

args=parser.parse_args()

try:
    print(f'Leyendo archivo {args.filename} ...')
    print(f'Usando direccion mac {args.reference} como referencia.')
    pcap=rdpcap(args.filename)
except Exception as e:
    print(e)

res={}
gtp_errors=0
other_errors=0

filtered_pcap=PacketList()

res_src={}
res_dst={}

for packet in pcap:
    if packet.haslayer(Ether) and (packet.getlayer(Ether).dst==args.reference or packet.getlayer(Ether).src==args.reference):
        filtered_pcap.append(packet)

percentage=len(filtered_pcap)*100/len(pcap)
print(f'Analizando el {str(percentage)} % de los paquetes.')

for packet in filtered_pcap:
    if packet.haslayer(IP): #solo se analizan paquetes ip
        try:
            if packet.haslayer(GTP_U_Header): #gtp u significa user data tunneling (datos de usuario=
                tos=str(int(packet.getlayer(GTP_U_Header).getlayer(IP).tos/4))#desencapsula y lee la ip, se divide entre cuatro para convertir de tos a dscp
            elif packet.haslayer(GTPHeader): #gtp heaer es filtrar gtp control (no hay paquetes?)
                tos=str(int(packet.getlayer(GTPHeader).getlayer(IP).tos/4))
            else:
                tos=str(int(packet.getlayer(IP).tos/4)) #otros paquetes ip
            if packet.getlayer(Ether).dst==args.reference:
                if tos in res_dst.keys():
                    res_dst[tos]+=1
                else:
                    res_dst.update({tos:1})
            elif packet.getlayer(Ether).src==args.reference:
                if tos in res_src.keys():
                    res_src[tos]+=1
                else:
                    res_src.update({tos:1})
        except Exception as e:
            other_errors+=1
print()
print('Paquetes salientes:')
for key in res_src.keys():
    print(f'DSCP {key}: {str(res_src[key])} paquetes')

print()
print('Paquetes entrantes:')
for key in res_dst.keys():
    print(f'DSCP {key}: {str(res_dst[key])} paquetes')

print()
print(f'{gtp_errors} errores de GTP.')
print(f'{other_errors} errores desconocidos.')
