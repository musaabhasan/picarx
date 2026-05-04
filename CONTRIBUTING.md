# Contributing

Useful contributions include:

- new read-only checks for Raspberry Pi / PiCar-X environments
- documentation for teaching lab hardening
- sample reports with synthetic data
- tests for parser behavior and edge cases
- clearer remediation guidance

## Development

```bash
python3 -m unittest discover -s tests
```

## Check Requirements

Every check should:

- be read-only
- avoid collecting secrets
- return a clear status: `pass`, `fail`, `warn` or `manual`
- include a short remediation note
- include tests where practical
