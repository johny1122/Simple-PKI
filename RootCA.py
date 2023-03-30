# Jonathan Birnbaum, 19.1.23

from CA import CA

ROOT_ID = 0


class RootCA(CA):
    """
    a class representing a Root CA. only one object of this class is assumed with
    the id of ROOT_ID (0)
    """

    def __init__(self, name: str):
        super().__init__(name, id=ROOT_ID)
