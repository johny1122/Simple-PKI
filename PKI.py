# Jonathan Birnbaum, 20.1.23

from Entity import Entity
from datetime import datetime, timedelta
from RootCA import RootCA
from CA import CA
from Verification_Authority import VerificationAuthority

# all_CAs is used only by the verifier (assuming as a trusted body) to get entity's public_key,
# parent CA id, revocation_list, certificates and cert_signatures for the verification process only
all_CAs = {}  # {ca_id : ca obj}


def main():
    verifier = VerificationAuthority(all_CAs)
    root_ca = RootCA('root_ca')  # root CA must be created first to get id 0 (the id of root CA)
    ca_1 = CA('ca_1')
    ca_2 = CA('ca_2')
    ent_1 = Entity('ent_1')
    ent_2 = Entity('ent_2')
    ent_3 = Entity('ent_3')
    ent_4 = Entity('ent_4')

    all_CAs[root_ca.get_id()] = root_ca
    all_CAs[ca_1.get_id()] = ca_1
    all_CAs[ca_2.get_id()] = ca_2

    print('\n==================== 1 ====================')
    # root_ca generate certificate for himself
    root_ca.generate_certificate(root_ca, is_entity_ca=True)

    # root_ca generate certificate for ca_1 and ca_2
    signature_ca_1, cert_ca_1 = root_ca.generate_certificate(ca_1, is_entity_ca=True)
    signature_ca_2, cert_ca_2 = root_ca.generate_certificate(ca_2, is_entity_ca=True)

    # check signature with root_ca public key -> success
    verifier.check_certificate(cert_ca_1, signature_ca_1, root_ca.get_id())
    verifier.check_certificate(cert_ca_2, signature_ca_2, root_ca.get_id())

    print('\n==================== 2 ====================')
    # ca_1 create certificate for ent_1
    signature_ent_1, cert_ent_1 = ca_1.generate_certificate(ent_1)

    # check signature with ca_1 public key -> success
    verifier.check_certificate(cert_ent_1, signature_ent_1, ca_1.get_id())
    # check signature with ca_2 public key -> fail because of wrong public key
    verifier.check_certificate(cert_ent_1, signature_ent_1, ca_2.get_id())

    print('\n==================== 3 ====================')
    # check chain of ca_1 to root_ca -> success
    verifier.check_chain(ca_1.get_id())

    print('\n==================== 4 ====================')
    # revoke ca_1 by root_ca
    root_ca.revoke_successor(ca_1.get_id())
    # check chain of ca_1 to root_ca -> fail because of revoke
    verifier.check_chain(ca_1.get_id())

    print('\n==================== 5 ====================')
    # ca_2 create certificate for ent_2 (starting from tomorrow)
    tomorrow = datetime.now() + timedelta(days=1)
    signature_ent_2, cert_ent_2 = ca_2.generate_certificate(ent_2, not_before=tomorrow)
    # check signature with ca_2 public key -> fail (because will be valid just from tomorrow)
    verifier.check_certificate(cert_ent_2, signature_ent_2, ca_2.get_id())

    print('\n==================== 6 ====================')
    # ca_2 create certificate for ent_3
    signature_ent_3, cert_ent_3, ent3_as_ca = ca_2.generate_certificate(ent_3, make_entity_ca=True)
    all_CAs[ent_3.get_id()] = ent3_as_ca  # change ent_3 with its CA object

    # check signature with ca_2 public key -> success
    verifier.check_certificate(cert_ent_3, signature_ent_3, ca_2.get_id())

    print('\n==================== 7 ====================')
    # ent3_as_ca create certificate for ent_4
    signature_ent_4, cert_ent_4 = ent3_as_ca.generate_certificate(ent_4)

    # check signature with ent3_as_ca public key -> success
    verifier.check_certificate(cert_ent_4, signature_ent_4, ent3_as_ca.get_id())

    print('\n==================== 8 ====================')
    # check chain of ent3_as_ca to root_ca -> success
    verifier.check_chain(ent3_as_ca.get_id())


main()
