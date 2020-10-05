


class BaseTX:
    """
    a transaction in a block
    """

    def __init__(self, hexdata=None):
        """ when hexdata is not None parse this tx from hex data """
