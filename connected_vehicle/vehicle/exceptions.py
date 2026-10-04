from __future__ import annotations


class VehicleDomainError(ValueError):
    """Base exception for Vehicle domain validation failures."""


class InvalidVINError(VehicleDomainError):
    """Raised when a VIN violates the domain contract."""


class InvalidVehicleIdError(VehicleDomainError):
    """Raised when a vehicle identifier is invalid."""


class InvalidTenantIdError(VehicleDomainError):
    """Raised when a tenant identifier is invalid."""


class InvalidVehicleTransitionError(VehicleDomainError):
    """Raised when a vehicle status transition is not allowed."""
