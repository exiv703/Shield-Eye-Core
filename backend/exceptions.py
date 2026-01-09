# Base exception for ShieldEye
class ShieldEyeException(Exception):
    pass

# Scanning errors
class ScanError(ShieldEyeException):
    pass

class ScanTimeoutError(ScanError):
    pass

class InvalidTargetError(ScanError):
    pass

class NetworkError(ScanError):
    pass

# CVE database errors
class CVEError(ShieldEyeException):
    pass

class CVEFetchError(CVEError):
    pass

class CVECacheError(CVEError):
    pass

# Validation and config errors
class ValidationError(ShieldEyeException):
    pass

class ConfigurationError(ShieldEyeException):
    pass

class SecurityPolicyError(ShieldEyeException):
    pass
