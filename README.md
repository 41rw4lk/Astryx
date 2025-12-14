# Astryx

**High-performance Coomer downloader with a local Web UI**

Astryx is a Windows-native downloader focused on **sustained throughput, reliability, and visibility** rather than burst scraping.  
It combines a high-performance backend with a real-time local Web UI.

---

## Features

### Local Web UI
- Runs locally at `http://127.0.0.1`
- Real-time telemetry, queue status, and logs
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

## Status

This is the **first public release**.  
The project is actively developed and focused on correctness, performance, and observability.

---

## Disclaimer

This project is for educational and personal use.  
Users are responsible for complying with applicable laws and site terms.
