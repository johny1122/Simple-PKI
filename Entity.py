# Jonathan Birnbaum, 20.1.23

from Utils import Utils
from Crypto.Hash import SHA256
from Crypto.Signature import DSS


class Entity:
    """
    a class representing an Entity which can sign objects and become a CA
    with a CA approval
    """

    def __init__(self, name: str, id=None):
        self.name = name
        self.id = id
        if id is None:
            self.id = Utils.generate_id()
        self.key = Utils.generate_private_public_keys()
        self.certificate = None
        self.cert_signature = None
        self.issuer_id = None

    def get_name(self) -> str:
        """
        returns the of the entity
        """
        return self.name

    def get_id(self) -> int:
        """
        returns the id of the entity
        """
        return self.id

    def get_public_key(self):
        """
        returns the public key of the entity
        """
        return self.key.public_key()

    def get_certificate(self):
        """
        returns the certificate the entity got from a CA
        """
        return self.certificate

    def get_cert_signature(self):
        """
        returns the signature of the certification a CA signed
        """
        return self.cert_signature

    def get_ca_issuer(self):
        """
        returns the id of the CA who signed the certificate
        """
        return self.issuer_id

    def set_issuer_id(self, issuer_id: int):
        """
        used when making an entity a CA. sets the approving CA id
        """
        if self.issuer_id is None:
            self.issuer_id = issuer_id

    def set_certificate(self, cert_signature, certificate):
        """
        used when making an entity a CA. sets the certificate from
        the approving CA
        """
        if self.cert_signature is None and self.certificate is None:
            self.cert_signature, self.certificate = cert_signature, certificate

    def sign(self, obj: bytes) -> bytes:
        """
        signs an object with DDS signing and returns the signature
        (https://pycryptodome.readthedocs.io/en/latest/src/signature/dsa.html)
        """
        h = SHA256.new(obj)
        signer = DSS.new(self.key, 'fips-186-3')
        signature = signer.sign(h)
        return signature
