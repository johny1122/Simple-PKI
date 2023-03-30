# Jonathan Birnbaum, 20.1.23

from datetime import datetime
from Entity import Entity
from Utils import Utils, VALIDITY_DURATION_DEFAULT
from Certificate import Certificate


class CA(Entity):
    """
    a class representing a CA. inherits the Entity class
    """

    def __init__(self, name: str, id=None):
        super().__init__(name, id)
        self.revocation_list = []
        self.successors = set()

    def get_revocation_list(self):
        """
        returns the CA's revocation list
        """
        return self.revocation_list

    def add_successor(self, entity_id: int):
        """
        adds an entity id to the successors set of the CA
        """
        self.successors.add(entity_id)

    def revoke_successor(self, entity_id: int):
        """
        revokes an entity with the entity_id id
        """
        if entity_id not in self.successors:  # can revoke only successor entity
            return
        self.successors.remove(entity_id)
        self.revocation_list.append(entity_id)

    def generate_certificate(self, entity: Entity, not_before: datetime = datetime.now(),
                             validity_duration_in_days: int = VALIDITY_DURATION_DEFAULT,
                             make_entity_ca: bool = False, is_entity_ca: bool = False):
        """
        generates a certificate for the given entity
        :param entity: entity to generate a certification for (just for easy access to id, name)
        :param not_before: datetime of beginning of certification validity
        :param validity_duration_in_days: int of days the verification will be valid after begin
        :param make_entity_ca: boolean if want to make the entity a CA
        :param is_entity_ca: boolean if the given entity is already a CA
        :return: returns the signature an certification created by the CA.
        if generating a certification to make the entity a CA, a new CA object will also
        be returned to be replaced by the given entity
        """
        cert = Certificate(entity, self, not_before, validity_duration_in_days,
                           make_entity_ca or is_entity_ca)
        cert_dict = cert.to_dict()
        cert_dict_as_bytes = Utils.obj_to_bytes(cert_dict)
        signature = self.sign(cert_dict_as_bytes)

        self.add_successor(entity.get_id())

        if make_entity_ca:  # only if need to change entity to CA (an Entity was given and not CA)
            entity_as_CA = CA(entity.get_name(), id=entity.get_id())
            entity_as_CA.set_certificate(signature, cert)
            entity_as_CA.set_issuer_id(self.get_id())
            return signature, cert, entity_as_CA

        else:
            entity.set_certificate(signature, cert)
            entity.set_issuer_id(self.get_id())
            return signature, cert
