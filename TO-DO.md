## Additions to the server

1. Generate plain HTML messages to be encrypted over TLS - **Done**
2. Additional display of PMS and Master secret reqd for verification with the result - **In Progress**

## Exploitation of the SSL server

1. Retrieve the decrypted PMS
2. Derive master secret from PMS
3. Derive the subsequent AES session keys and decrypt the message sent by the server
4. Use case scenario for a forged signature (PoC?)

## Analysis of the attack

1. Figure out why the attack on BouncyCastle didn't work and fix the script accordingly for false positives and negatives
