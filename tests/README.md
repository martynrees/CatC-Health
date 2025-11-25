# Catalyst Center Health Monitor - Test Suite

This directory contains unit tests for the Catalyst Center Health Monitor.

## Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=catc_health --cov-report=html

# Run specific test file
pytest tests/test_health_monitor.py

# Run with verbose output
pytest -v
```

## Test Structure

- `test_health_monitor.py` - Main test suite
- `conftest.py` - Pytest fixtures and shared test data
- `fixtures/` - Sample data files for testing

## Writing Tests

When adding new features, please include corresponding unit tests:

1. Test happy path scenarios
2. Test error handling
3. Test edge cases
4. Mock external API calls

## Coverage Goals

- Aim for >80% code coverage
- Focus on critical business logic
- All public APIs should have tests
