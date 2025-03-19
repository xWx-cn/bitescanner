class ScannerException(Exception): pass
class PrivilegeError(ScannerException):
    def __init__(self):
        super().__init__("Root/admin privileges required for SYN scan")
class NetworkError(ScannerException): pass