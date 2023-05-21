# PyCrypt

A rudimentary encryption program written in Python. Planning to maintain this separately from [PyCryptX,](https://github.com/xannythepleb/PyCryptX) the version with X25519 public key encryption.

Currently it is able to encrypt any file using a chosen password. The password generates a key using PBKDF2 with BLAKE2b as the hashing algorithm. The password is salted and hashed. The ChaCha20-Poly1305 cipher then uses the password derived key along with a random nonce to encrypt the file.

Tested with multiple formats and it was able to encrypt and decrypt text files and media files. I also found the use of BLAKE2b significantly decreased the size of encrypted files compared to conventional SHA256 as well as providing improvements in speed and security.

To do:

* ~~Add public key cryptography~~
* Display public keys in friendly human readable format
* Store encrypted files with base64 formatting
* Add signatures and signature verification via Ed25519
* Integrate this with the public key encryption - so you have one public key that can encrypt and sign

**Please note this is an unaudited hobby project! If security is vital, use Signal or PGP.**
