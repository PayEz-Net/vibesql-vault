# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-03-25

### Added
- Governed opaque storage vault for encrypted JSONB data
- PCI DSS v4.0 Requirement 3 audit brief (Rev 4 architecture)
- Phase 2A: vault retention policies with configurable lifecycle management
- PATCH access policy check and admin sweep route for vault entries
- TLS support with separate dev and production modes
- Mandatory retention policy enforcement on all stored data
- Blocking audit trail, caller identity tracking, access policy enforcement, and purge proof logging

### Fixed
- PCI audit finding: blocking audit writes now guaranteed before response
- PCI audit finding: caller identity propagated through all vault operations
- PCI audit finding: access policy enforcement on all entry reads
- PCI audit finding: purge operations produce cryptographic proof
- PCI findings 5 and 6: TLS mode separation (dev/prod) and mandatory retention policy
- HOTFIX: PATCH access policy check was bypassing authorization on certain routes
- Cargo.lock and Dockerfile alignment for Phase 2A build

### Changed
- Scaled back PCI claims to reflect vault as governed dry storage, not an encryption proxy
- Rewrote README to accurately describe governed opaque storage vault architecture (Rev 4)
