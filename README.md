# PyCrypt

A rudimentary encryption program written in Python. Plan to add a lot more functionality soon.

Currently it is able to encrypt any file using a chosen password. The password generates a key using PBKDF2 with BLAKE2b as the hashing algorithm. The password is salted with a random nonce and hashed. The ChaCha20-Poly1305 cipher then uses this password derived key to encrypt the file.

**Please note this is an unaudited hobby project! If security is vital, use Signal or PGP.**
