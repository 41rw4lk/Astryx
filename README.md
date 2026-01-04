# Astryx

**High-performance Coomer downloader with a local Web UI**

Astryx is a Windows-native downloader focused on **sustained throughput, reliability, and visibility** rather than burst scraping.  
It combines a high-performance backend with a real-time local Web UI.

<img width="1913" height="920" alt="530176039-bfdcd326-8fa6-46e1-b3aa-8858261d396f" src="https://github.com/user-attachments/assets/77197507-fdbe-404f-b67c-49f38dccaaf6" />
Real-time local Web UI showing throughput, host health, and download state.

---

![GitHub release](https://img.shields.io/github/v/release/41rw4lk/Astryx?label=release)
![License](https://img.shields.io/github/license/41rw4lk/Astryx)
![Stars](https://img.shields.io/github/stars/41rw4lk/Astryx)
![Forks](https://img.shields.io/github/forks/41rw4lk/Astryx)
![Downloads](https://img.shields.io/github/downloads/41rw4lk/Astryx/total)
![Last commit](https://img.shields.io/github/last-commit/41rw4lk/Astryx)

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20me%20a%20coffee-support-%23FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/YOURNAME)

## Project Status

Astryx is an independently developed project released publicly as an early v0.x build.
The project is actively developed and may evolve as the implementation continues to be refined.

The codebase evolved organically to address real-world reliability and performance concerns, rather than to prioritize showcase-level architecture or strictly idiomatic patterns.

Some areas are intentionally monolithic or redundant in favor of:
- debuggability
- predictable behavior
- sustained throughput

Refactoring and cleanup or are going, but not required for effective use.

---

## Features

### Local Web UI
- Runs locally at `http://127.0.0.1`
- Real-time local telemetry (queue status, host health, logs)
- No external server or cloud dependency
- Browser-based control panel

### Download Engine
- High-performance, sustained download pipeline
- Separate worker pools for:
  - **NV** — images & non-video media  
  - **VID** — video downloads
- Tunable concurrency per media type
- Designed for long-running sessions, not burst scraping

### Host Health & Routing
- Live host latency tracking
- Automatic pinning of best-performing hosts
- Graceful degradation when hosts slow or fail
- Real-time host health visualization

### Authentication
- Playwright-based login support
- Reliable handling of authenticated sessions
- Optional credential saving via **Save** toggle
- Automatic login when credentials are available

### Platform
- Windows x64
- Portable (no installer)
- No external dependencies beyond included files

---

## Project History

This project began as a WinForms application named `CMDownloaderUI`,
was later rebranded as `AstroFetch`,
and has since evolved into a Web UI–first application named `Astryx`.

The WinForms layer currently remains as a Windows host shell responsible for:
- process lifetime
- system integration
- orchestration of background workers

The primary user interface is the local Web UI.

---

## What This Project Is / Is Not

**This is:**
- A practical, Windows-native tool
- Optimized for long-running, observable workloads
- Built to solve specific problems encountered in real use

**This is not:**
- A framework
- A reference implementation
- An example of ideal or minimal C# architecture

---

## Safety & Privacy

- Runs entirely locally
- No external telemetry (nothing is sent off-machine)
- No cloud services
- No automatic uploads
- No bundled credentials

All network activity is user-initiated.

## Disclaimer

This project is for educational and personal use.  
Users are responsible for complying with applicable laws and site terms.
