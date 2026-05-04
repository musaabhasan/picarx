# PiCar-X Security Baseline Toolkit

Read-only security baseline checks and documentation for Raspberry Pi / PiCar-X style robotics labs.

This project is intended for educators, lab managers, students and security teams who need a practical starting point for hardening small Linux-based robotics devices without turning a teaching lab into an enterprise security program.

## Why This Exists

Robotics and IoT teaching kits are often deployed quickly, reused by many learners and connected to shared networks. Small defaults can become real operational risks:

- unchanged hostnames and default users
- permissive SSH settings
- missing firewall posture
- unclear lab ownership
- weak documentation around setup, recovery and teardown

The toolkit provides a lightweight baseline report that helps teams review those items consistently.

## What It Checks

The CLI performs read-only checks against a target filesystem root:

- operating system metadata from `/etc/os-release`
- SSH password authentication and root login settings
- default Raspberry Pi user presence
- default hostname usage
- firewall tooling indicators
- sudo `NOPASSWD` entries

It does not modify the device.

## Quick Start

```bash
python3 -m picarx_security_baseline --format markdown
```

Run against a mounted Raspberry Pi filesystem:

```bash
python3 -m picarx_security_baseline --root /Volumes/pi-root --format json
```

Write a report:

```bash
python3 -m picarx_security_baseline --format markdown --output reports/baseline.md
```

## Development

Run tests with the standard library test runner:

```bash
python3 -m unittest discover -s tests
```

## Repository Direction

Planned improvements:

- add sample reports for teaching labs
- add optional YAML policy profiles
- add checks for wireless configuration hygiene
- add GitHub Actions validation
- add a hardening worksheet for classroom rollout

## Safety

This tool is diagnostic. Review findings with the lab owner before changing a device, especially in teaching environments where remote access and permissive settings may have been intentionally configured for a class exercise.
