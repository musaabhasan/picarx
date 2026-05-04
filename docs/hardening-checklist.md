# PiCar-X Lab Hardening Checklist

Use this checklist before connecting robotics kits to a shared lab, school or institutional network.

## Identity and Ownership

- Assign each kit a visible asset ID.
- Record the hostname, MAC address and responsible owner.
- Replace generic hostnames such as `raspberrypi`.
- Keep a recovery image or rebuild note for each lab cohort.

## Access

- Disable unused accounts.
- Replace default passwords before network use.
- Prefer SSH keys for administrative access.
- Disable SSH root login.
- Disable SSH password authentication when feasible.
- Document any teaching exception that requires temporary password access.

## Network

- Segment lab devices from administrative systems.
- Restrict inbound access to required services.
- Confirm firewall tooling or equivalent network controls.
- Avoid exposing robotics devices directly to the internet.
- Review wireless credentials before reusing images across cohorts.

## Operations

- Patch base images before each course or workshop.
- Keep a short change log for lab images.
- Document reset steps for instructors.
- Remove learner files before reassigning kits.
- Review logs after public demonstrations or competitions.

## Data

- Do not store learner personal data on robotics devices.
- Do not commit Wi-Fi credentials, API keys or tokens to course repositories.
- Use synthetic datasets for demonstrations.

## Review Rhythm

- Before each cohort: rebuild or patch images.
- During delivery: monitor device availability and network behavior.
- After delivery: wipe devices, rotate shared credentials and archive notes.
