# Baiduyun Downloader

Baidu Cloud disk file downloader for Windows.

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey) ![License](https://img.shields.io/badge/License-MIT-green)

## Features

- Multi-connection parallel download (default 8 connections per file)
- Concurrent file downloads (default 2 files)
- Pause / Resume / Cancel / Auto-retry
- Download shared links (with extract code)
- Resume interrupted downloads
- Speed limit & connection settings
- System tray with download status
- BDUSS encrypted storage (Windows DPAPI)
- 4 languages: English, Korean, Japanese, Chinese

## Download

[Releases](https://github.com/DreamingStrawberry/Baiduyun-Downloader/releases) page:

- **BaiduyunDownloader.exe** - Portable (no install needed)
- **BaiduDownloader_Setup.exe** - Installer

## Usage

1. Run the app
2. Login with BDUSS cookie
3. Browse files or paste a shared link
4. Select files and download

### How to get BDUSS

1. Login to [pan.baidu.com](https://pan.baidu.com) in your browser
2. Open DevTools (F12) > Application > Cookies
3. Copy the `BDUSS` value

## Build

```bash
pip install PySide6 requests pyinstaller pywin32
python -m PyInstaller BaiduDownloader.spec --noconfirm
```

## License

MIT
