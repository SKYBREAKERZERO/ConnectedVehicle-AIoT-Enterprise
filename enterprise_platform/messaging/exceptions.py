from __future__ import annotations


class MessagingError(Exception):
    """Base exception for messaging platform failures."""


class MessagePublishError(MessagingError):
    """Raised when a message cannot be published."""

    def __init__(self) -> None:
        super().__init__("The message could not be published.")


class MessageReceiveError(MessagingError):
    """Raised when messages cannot be received."""

    def __init__(self) -> None:
        super().__init__("Messages could not be received.")


class MessageDeleteError(MessagingError):
    """Raised when a consumed message cannot be deleted."""

    def __init__(self) -> None:
        super().__init__("The message could not be deleted.")


class InvalidMessageError(MessagingError):
    """Raised when a received message violates the event contract."""

    def __init__(self) -> None:
        super().__init__("The received message is invalid.")
