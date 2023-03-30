# Jonathan Birnbaum, 20.1.23

from datetime import datetime
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from RootCA import ROOT_ID
from Utils import color_text, Colors, Utils
from Certificate import Certificate


class VerificationAuthority:
    """
    class of a verification authority
    """

    def __init__(self, all_CAs):
        self.all_CAs = all_CAs

    def check_signature_validity(self, obj: bytes, signature: bytes, signer_id: int) -> bool:
        """
        check the validity of the signature of CA with signer_id id on the obj.
        returns True if valid and False otherwise
        """
        h = SHA256.new(obj)
        verifier = DSS.new(self.all_CAs[signer_id].get_public_key(), 'fips-186-3')
        try:
            verifier.verify(h, signature)
            return True
        except ValueError:
            return False

    def check_certificate(self, cert: Certificate, signature: bytes, signer_id: int) -> bool:
        """
        check the validity of the certificate with signature signed by CA with signer_id id.
        check the if the sign is valid and also if the certificate is valid now (according to
        valid dated)
        returns True if valid and False otherwise
        """
        cert_dict = cert.to_dict()
        cert_as_bytes = Utils.obj_to_bytes(cert_dict)
        is_sign_valid = self.check_signature_validity(cert_as_bytes, signature, signer_id)
        if not (cert.not_before <= datetime.now() <= cert.not_after):  # check dates validity
            print(f'Certificate check {color_text("Failed", Colors.RED)} - Certificate dates are not '
                  f'valid for current time!')
            return False

        if is_sign_valid:
            print(f'Certificate check {color_text("Passed", Colors.GREEN)} - Signature of '
                  f'signer id {signer_id} match!')
            return True
        else:
            print(f'Certificate check {color_text("Failed", Colors.RED)} - Signature of signer '
                  f'id {signer_id} does not match!')
            return False

    def check_chain(self, validate_ca_id: int):
        """
        checks the if the chain of the given CA id is valid (top CA is Root CA)
        """
        curr_ca_id = validate_ca_id
        validate_ca = self.all_CAs[curr_ca_id]
        parent_ca_id = validate_ca.get_ca_issuer()

        # cross over all chain until Top CA
        while parent_ca_id != curr_ca_id:  # while parent ca id different from ca id -> not root ca
            # check revocation list
            parent_ca = self.all_CAs[parent_ca_id]
            if curr_ca_id in parent_ca.get_revocation_list():
                print(f'Chain check {color_text("Failed", Colors.RED)} - CA {curr_ca_id} is '
                      f'in revocation list!')
                return False

            # check certification signature
            is_signature_valid = self.check_certificate(validate_ca.get_certificate(),
                                                        validate_ca.get_cert_signature(), parent_ca_id)
            if not is_signature_valid:
                return False

            curr_ca_id = parent_ca_id
            validate_ca = self.all_CAs[curr_ca_id]
            parent_ca_id = validate_ca.get_ca_issuer()

        # from now only highest CA (Root) is left to check
        higher_ca_id = validate_ca.get_id()
        if higher_ca_id != ROOT_ID:
            print(f'Chain check {color_text("Failed", Colors.RED)} - Top CA {higher_ca_id} is not root CA!')
            return False

        is_signature_valid = self.check_certificate(validate_ca.get_certificate(),
                                                    validate_ca.get_cert_signature(), higher_ca_id)
        if not is_signature_valid:
            return False

        print(f'Validity chain check for CA {validate_ca_id} {color_text("Passed", Colors.GREEN)}!')
        return True
