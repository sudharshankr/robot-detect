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

"""


class Decrypt:
    def __init__(self, pms_hex, client_r, server_r):
        self.pms = bytes.fromhex("000" + pms_hex[2:])[-48:]
        self.client_random = bytes.fromhex(client_r[2:])
        self.server_random = bytes.fromhex(server_r[2:])
        self.master_secret = ""
        self.client_write_key = ""
        self.server_write_key = ""
        self.client_write_iv = ""
        self.server_write_iv = ""
        self.mac_length = 20
        self.compute_master_secret()
        self.compute_keys()

    def compute_master_secret(self):
        seed0 = self.client_random + self.server_random
        label = b'master secret'
        seed1 = label + seed0
        A0 = seed1
        A1 = hmac.new(self.pms, A0, digestmod=hashlib.sha256).digest()
        A2 = hmac.new(self.pms, A1, digestmod=hashlib.sha256).digest()
        P_hash = hmac.new(self.pms, A1 + seed1, digestmod=hashlib.sha256).digest() + hmac.new(self.pms, A2 + seed1,
                                                                                              digestmod=hashlib.sha256).digest()
        self.master_secret = P_hash[:48]

    def compute_keys(self):
        master_seed = b'key expansion' + self.server_random + self.client_random
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
        self.client_write_key = keys[40:72]
        self.server_write_key = keys[72:104]
        self.client_write_iv = keys[104:120]
        self.server_write_iv = keys[120:136]

    def decrypt_app_data(self, side, app_data):
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


# if __name__ == "__main__":
#     a = "0x2f2d9ab7aa01e14c51a86d7e4e21e8141862d868e284baba8a45546a58356af14eff342ae748da0abc74373a0a80d19584b2ef879f036b5ff2b769a71047a442af01b8798aaba1e320ed123919cd20aadb2e17f6e4455618aa535744fe20ac684885134d9054495d7f78db1d67ec6f5330d2e8cd5bf0c56f879e951d1c0f3b8abc04aecb2cdf8d9cf7d64b45210b3629ef08ea6c421b079fa7ac03b937eda4d6afb6a0aecf5961ee108b49baa0feb6ab4f080de66daacf6abdefe9a83a3f76d0c61a8cadc1cba724855932f9a1000030342a50f8d874af5ea650a7f6469c98ae8c057c5adb0ce732e3aa9af153600fb7d33fb0d0ad34024be24b9913488b70303C3530D28A7172B3BADDB24EA5D605A9B7D2F05549F355DD85AEBA46288873CE178A87891B42383A84CFB3A9BEDC4"
#     dec = Decrypt(a, "0x6844f918ef23051e59f00834e4f251a0675d0f831c26cb214a4c404214bad614",
#                   "0x5e999839c5fc1f0726046b43a1f2c8ee23c0ac2ab95769a085f4ad2235a30206")
#     app_data = "164b7a67414ae1b710db98fc36cfc3abe2b1f961fe03b575888abe093c9065b25c816ad2c2369f86d15ed0cfce48710f7e9f6d792c884a37d091458e3014636cb0c1500d82cbf625bb83ef9c7f75d8c28a6dbe495fde9d53e84a53afd470231252e67ff7d38650902ad267fac6af7e82dd6fb6f766b9581ba3fb4bc30692541d507c6aebfffe19591e8e056490c91fcb01f910b6f21057909e9cb6ef0b5c687b354701c7607cf64fb03ded89411cb0a179ff8654fbaab507cc6ea76610a80ec63ba5525d8a9843c65f0a63d35219a04d9f5ac6900bd626b70d4ca0db9685af1a43cf4d9f3d006788bb359477ddfbb906da25e9c142f126cdf0da857462693528f9c171eeb7612f48085dcc030d271b769678fe6c4823ae547a18c14a3162a9ac0489a303c46597d6eb558757c74e96be58b49271c44a79c6e41e9243aee3027b"
#     dec_data = dec.decrypt_app_data("server", app_data)
#     print(dec_data)

