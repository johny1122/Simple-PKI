# Jonathan Birnbaum, 20.1.23

from Crypto.PublicKey import ECC
import pickle

VALIDITY_DURATION_DEFAULT = 10


class Utils:
    """
    class of utils static methods
    """
    id_counter = 0

    @staticmethod
    def generate_id() -> int:
        """
        returns a new fresh id
        """
        Utils.id_counter += 1  # assume Root CA has id 0 so start with 1
        return Utils.id_counter

    @staticmethod
    def generate_private_public_keys():
        """
        returns a key containing a private and public key
        """
        key = ECC.generate(curve='P-256')
        return key

    @staticmethod
    def obj_to_bytes(obj) -> bytes:
        """
        returns the given object as bytes
        """
        return pickle.dumps(obj)

    @staticmethod
    def bytes_to_obj(obj_as_bytes: bytes):
        """
        returns an object represented by the given  bytes
        """
        return pickle.loads(obj_as_bytes)


def color_text(text, rgb):
    r, g, b = rgb
    return f"\033[38;2;{r};{g};{b}m{text}\033[0m"


class Colors:
    BLACK = (0, 0, 0)
    RED = (255, 0, 0)
    GREEN = (0, 255, 0)
    BLUE = (0, 0, 255)
    YELLOW = (255, 255, 0)
    CYAN = (0, 255, 255)
