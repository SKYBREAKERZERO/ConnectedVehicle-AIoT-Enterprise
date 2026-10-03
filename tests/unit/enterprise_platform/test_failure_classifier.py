from __future__ import annotations

from enterprise_platform.reliability.failure import (
    ExceptionTypeFailureClassifier,
    FailureDisposition,
)


def test_failure_classifier_marks_configured_exception_retryable() -> None:
    classifier = ExceptionTypeFailureClassifier(
        (
            TimeoutError,
            ConnectionError,
        )
    )

    result = classifier.classify(TimeoutError("temporary"))

    assert result is FailureDisposition.RETRYABLE


def test_failure_classifier_supports_exception_subclasses() -> None:
    classifier = ExceptionTypeFailureClassifier((ConnectionError,))

    result = classifier.classify(ConnectionResetError("temporary"))

    assert result is FailureDisposition.RETRYABLE


def test_failure_classifier_defaults_to_non_retryable() -> None:
    classifier = ExceptionTypeFailureClassifier((TimeoutError,))

    result = classifier.classify(ValueError("invalid input"))

    assert result is FailureDisposition.NON_RETRYABLE


def test_failure_classifier_can_disable_all_retries() -> None:
    classifier = ExceptionTypeFailureClassifier(())

    result = classifier.classify(RuntimeError("failure"))

    assert result is FailureDisposition.NON_RETRYABLE
