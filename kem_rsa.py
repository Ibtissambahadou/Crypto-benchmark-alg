from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os

class RSAKem:
    def keygen(self):
        # ↓ ça, c'est l'appel à la vraie lib cryptography
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        # ↓ on "emballe" le résultat au format bytes, pour que ça rentre dans notre contrat
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        pub_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pub_bytes, priv_bytes

    def encaps(self, public_key_bytes):
        public_key = serialization.load_der_public_key(public_key_bytes)
        secret = os.urandom(32)  # on génère nous-mêmes le secret (RSA ne le fait pas pour nous)
        ciphertext = public_key.encrypt(
            secret,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        return ciphertext, secret

    def decaps(self, private_key_bytes, ciphertext):
        private_key = serialization.load_der_private_key(private_key_bytes, password=None)
        secret = private_key.decrypt(
            ciphertext,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None)
        )
        return secret
