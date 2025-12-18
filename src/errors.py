from __future__ import annotations


class CapabilityError(Exception):
    pass


class CapabilityNotFoundError(CapabilityError):
    pass


class CapabilityManifestError(CapabilityError):
    pass


class CapabilityPolicyError(CapabilityError):
    pass


class CapabilityInstallError(CapabilityError):
    pass


class CapabilityRunError(CapabilityError):
    pass

