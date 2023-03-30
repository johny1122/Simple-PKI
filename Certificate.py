# Jonathan Birnbaum, 20.1.23

from Entity import Entity
from datetime import datetime, timedelta


class Certificate:
    """
    class of certificate. save the certificate information details
    """

    def __init__(self, granted_to_id: Entity, granted_by_id, not_before: datetime,
                 validity_duration_in_days: int, make_ca: bool):
        self.granted_to_id = granted_to_id.id
        self.granted_by_id = granted_by_id.id
        self.not_before = not_before
        self.not_after = not_before + timedelta(days=validity_duration_in_days)
        self.make_ca = make_ca

    def to_dict(self):
        """
        return a dict with all the certificate details
        """
        return {'granted_to_id': self.granted_to_id,
                'granted_by_id': self.granted_by_id,
                'not_before': self.not_before.strftime("%d/%m/%Y %H:%M:%S"),
                'not_after': self.not_after.strftime("%d/%m/%Y %H:%M:%S"),
                'make_ca': self.make_ca}
