
class NoChildSAException(Exception):
    """
    Exception raised if there is no Child SA under current IKE SA
    """

    def __init__(self):
        self.message = "There is no Child SA under current IKE SA"
        
class NoIKESAException(Exception):
    """
    Exception raised if there is no IKE SA
    """

    def __init__(self):
        self.message = "There is no IKE SA"
        
class HaveRekeyedException(Exception):
    """
    Exception raised if already rekeyed
    """

    def __init__(self):
        self.message = "Already rekeyed"
        
class UnSupportedException(Exception):
    """
    Exception raised if already rekeyed
    """

    def __init__(self):
        self.message = "Already rekeyed"

