"""
conftest.py — shared pytest configuration.

Sets asyncio_mode = "auto" so every async test function runs automatically
without needing @pytest.mark.asyncio on each one.
"""
import pytest

# Allow all async tests to run without explicit mark
def pytest_configure(config):
    config.addinivalue_line(
        "markers", "asyncio: mark test as async"
    )
