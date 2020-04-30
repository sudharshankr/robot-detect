from Crypto.Util.Padding import unpad
import hmac
import hashlib
from Crypto.Cipher import AES

"""
Usage: define an object with the decrypted PMS, client_random and server_random. Then call the decrypt_app_data() fn.

decrypt_app_data(side, data) : 
    parameters:
        side = "client" : when data passed is the one transmitted from client to server. (for example, HTTP request)
        side = "server" : when data passed is the one transmitted from server to client. (for example, HTTP response)

example:
    # pms recieved from the bliechenbacher's attack script
    pms = "0x2f2d9ab7aa01e14c51a86d7e4e21e8141862d868e284baba8a45546a58356af14eff342ae748da0abc74373a0a80d19584b2ef879f036b5ff2b769a71047a442af01b8798aaba1e320ed123919cd20aadb2e17f6e4455618aa535744fe20ac684885134d9054495d7f78db1d67ec6f5330d2e8cd5bf0c56f879e951d1c0f3b8abc04aecb2cdf8d9cf7d64b45210b3629ef08ea6c421b079fa7ac03b937eda4d6afb6a0aecf5961ee108b49baa0feb6ab4f080de66daacf6abdefe9a83a3f76d0c61a8cadc1cba724855932f9a1000030342a50f8d874af5ea650a7f6469c98ae8c057c5adb0ce732e3aa9af153600fb7d33fb0d0ad34024be24b9913488b70303C3530D28A7172B3BADDB24EA5D605A9B7D2F05549F355DD85AEBA46288873CE178A87891B42383A84CFB3A9BEDC4"
    
    # client_random and server_random extracted from pcap file
    client_random = "6844f918ef23051e59f00834e4f251a0675d0f831c26cb214a4c404214bad614"
    server_random = "5e999839c5fc1f0726046b43a1f2c8ee23c0ac2ab95769a085f4ad2235a30206"
    
    # defining the Decrypt object and then decrypting the data 
    dec = Decrypt(pms, client_random, server_random) # all the values passed are in hex
    plaintext_data = dec.decrypt_app_data("server", enc_data) # for decrypting HTTP response.
    
example for session resumption:
    plaintext_data = dec.decrypt_app_data("client", enc_data, 1, new_client_random, new_server_random)

"""


class Decrypt:
    def __init__(self, pms_hex, client_r, server_r):
        self.pms = bytes.fromhex("000" + pms_hex[2:])[-48:]
        self.master_secret = ""
        self.client_write_key = ""
        self.server_write_key = ""
        self.client_write_iv = ""
        self.server_write_iv = ""
        self.mac_length = 20
        self.compute_master_secret(bytes.fromhex(client_r[2:]), bytes.fromhex(server_r[2:]) )

    def compute_master_secret(self, client_random, server_random):
        seed0 = client_random + server_random
        label = b'master secret'
        seed1 = label + seed0
        A0 = seed1
        A1 = hmac.new(self.pms, A0, digestmod=hashlib.sha256).digest()
        A2 = hmac.new(self.pms, A1, digestmod=hashlib.sha256).digest()
        P_hash = hmac.new(self.pms, A1 + seed1, digestmod=hashlib.sha256).digest() + hmac.new(self.pms, A2 + seed1,
                                                                                              digestmod=hashlib.sha256).digest()
        self.master_secret = P_hash[:48]
        self.compute_keys(client_random, server_random)

    def compute_keys(self, client_random, server_random):
        master_seed = b'key expansion' + server_random + client_random
        master_0 = master_seed
        master_1 = hmac.new(self.master_secret, master_0, digestmod=hashlib.sha256).digest()
        master_2 = hmac.new(self.master_secret, master_1, digestmod=hashlib.sha256).digest()
        master_3 = hmac.new(self.master_secret, master_2, digestmod=hashlib.sha256).digest()
        master_4 = hmac.new(self.master_secret, master_3, digestmod=hashlib.sha256).digest()
        master_5 = hmac.new(self.master_secret, master_4, digestmod=hashlib.sha256).digest()
        keys = hmac.new(self.master_secret, master_1 + master_seed, digestmod=hashlib.sha256).digest() \
               + hmac.new(self.master_secret, master_2 + master_seed, digestmod=hashlib.sha256).digest() \
               + hmac.new(self.master_secret, master_3 + master_seed, digestmod=hashlib.sha256).digest() \
               + hmac.new(self.master_secret, master_4 + master_seed, digestmod=hashlib.sha256).digest() \
               + hmac.new(self.master_secret, master_5 + master_seed, digestmod=hashlib.sha256).digest()

        """
        computing keys for AES-256-CBC-SHA
        """
        self.mac_length = 20
        self.client_write_key = keys[40:56]
        self.server_write_key = keys[56:72]
        self.client_write_iv = keys[72:88]
        self.server_write_iv = keys[88:104]


    def decrypt_app_data(self, side, app_data, resumption=0, client_random="", server_random=""):
        if resumption == 1:
            self.compute_keys(client_random, server_random) # recomputing fresh keys in case of session resumption
        if type(app_data) is str:
            app_data = bytes.fromhex(app_data)
        try:
            # side = client -> client to server. Decryption on the server side. So use client_write_key
            if side == "client":
                cipher = AES.new(self.client_write_key, AES.MODE_CBC, self.client_write_iv)  # defining the cipher
                pt_data = unpad(cipher.decrypt(app_data), 16)[:-self.mac_length]

            elif side == "server":
                cipher = AES.new(self.server_write_key, AES.MODE_CBC, self.server_write_iv)  # defining the cipher
                pt_data = unpad(cipher.decrypt(app_data), 16)[:-self.mac_length]

        except Exception as e:
            print("Decryption failed: ", e)
            return ""

        return pt_data[16:].decode('ascii', errors="ignore")

#
# if __name__ == "__main__":
#     a = "0x2f2d9ab7aa01e14c51a86d7e4e21e8141862d868e284baba8a45546a58356af14eff342ae748da0abc74373a0a80d19584b2ef879f036b5ff2b769a71047a442af01b8798aaba1e320ed123919cd20aadb2e17f6e4455618aa535744fe20ac684885134d9054495d7f78db1d67ec6f5330d2e8cd5bf0c56f879e951d1c0f3b8abc04aecb2cdf8d9cf7d64b45210b3629ef08ea6c421b079fa7ac03b937eda4d6afb6a0aecf5961ee108b49baa0feb6ab4f080de66daacf6abdefe9a83a3f76d0c61a8cadc1cba724855932f9a1000030342a50f8d874af5ea650a7f6469c98ae8c057c5adb0ce732e3aa9af153600fb7d33fb0d0ad34024be24b9913488b70303842122AA292C1381BEE69256A2BD7A745CDB7EBFFBC72B8D803985D0B3C74AC728F327D43C1686DC0B97410A3986"
#     client_random = "0xca7f782f47c216b0709f65ec64e32f41d274bfa9fd4ff379b0761d98fca0c652"
#     server_random = "0x5eaae294038f37b614442516e1fa3676884fe8b326fb17056b347b155db3f1c9"
#     dec = Decrypt(a, client_random, server_random)
#     app_data = "133f732da19d2fcf4466f5b10b4e60c409dc4f517678249cb66321325ba17e4e59182acf562fac1415323d5b861cf6bea366aa87a2e7bec5e78386d7cb8a1a492be7b75f1cc12dd6e83d9bddb9af5fa120806f3b40e81cabc0a1f91431195f8ec83936d58f38c5fe314ce8e0cc770cdfecb6021065550670f780452af288f7373d80906f7bc66bd32102e7fedb84e39de87abecb2f5c250f5ef7e1cd487d5a0a69d06dc525a5cb9334d1b79fe32bf0087080facb731062f7a7ce7d108cdee4664a28aef768833ded2d61f89c7394bfc6a9a99c32c50e874358e7c9be20a5adbd7a367c14357c55f2e50a0ded839959663077e73c5d7ed587b147cf02b54b3dc0579d22f1811ed5d8ad9fab5f6cc937bfa6a2123fcea1a28e5d6136e212893578e961b1b6c1a67188c3c3dd2abf7ffac8655e2c1baaad73a70198a0332dc1e0c620faa1c5a7f8c47f25a657b102ae55b685bb24a3c03f2c73414176a005c391fa5d5d7f93b786773031274c11f4f4e4d1bb04fb29521e2b9bb7094109067699b8ab6579ed76dc63798cd493b00c24aa4de525c427e78dd43c930bd591dbaf037b8273341829ea56c3deb4a181064cb2fd5cc84d43c459e2163988dc62dc1b9622e5169f2614dcba8054185dc860cdda0831dbaa07c0739423fdd76ae60ebcca4f"
#     # dec_data = dec.decrypt_app_data("client", app_data)
# the below code is for session resumption
#     client_random = "0xb413b087e8f0758a7d106dcf1d42bdeeba20deab22ff2460416fff6e195596e9"
#     server_random = "0x5eaae29496ecaa107244aea2bd9369bfe45fda25199d9d283027920b2df7b6b2"
#     dec_data = dec.decrypt_app_data("client", app_data, 1, bytes.fromhex(client_random[2:]), bytes.fromhex(server_random[2:]))
#     print(dec_data)

