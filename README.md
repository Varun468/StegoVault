# StegoVault

StegoVault is an offline-first, localhost-only application for encrypting text
or files and embedding them in images. It uses standard AES-256-GCM for data
encryption. Its DPLE workflow chooses a keyed order for RGB least-significant
bits; **steganography is not undetectable and is not a substitute for
encryption**.

## Features

- Text, Unicode, and arbitrary file payloads, including PDF, TXT, DOCX, ZIP,
  and binary files.
- PNG/BMP images can be hidden as file payloads and extracted byte-for-byte.
- AES-256-GCM encryption, Scrypt password-based key derivation, fresh salt and
  nonce per operation, and authenticated payload/header integrity checks.
- Lossless PNG output, capacity/utilization reporting, PSNR and SSIM analysis.
- Optional SQLite operation and security-event history. It records only
  operation type, payload type/size, dimensions, and timestamps; it does not
  record passwords, filenames, or payload contents.
- Dashboard, hide/extract, image analysis, security center, and settings pages.

## Requirements and installation

- Windows and Python 3.11 or newer
- Packages in `requirements.txt`

In PowerShell, from the project directory:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

For an already-offline computer, first download compatible wheels for the
target Windows/Python version into a local wheelhouse on an approved connected
computer, then transfer the wheelhouse using local media:

```powershell
python -m pip install --no-index --find-links C:\wheelhouse -r requirements.txt
```

After installation, choose `.venv\Scripts\python.exe` as the VS Code Python
interpreter. The app does not download packages or make application-level
external network requests at runtime.

## Run

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

Open `http://127.0.0.1:8501` on the same computer. Streamlit configuration is
in `.streamlit/config.toml` (the standard Streamlit configuration path):

- `server.address = "127.0.0.1"`
- `server.port = 8501`
- `server.maxUploadSize = 64`
- `browser.gatherUsageStats = false`
- Dark theme enabled

The application also stops if Streamlit's effective server address is not
`127.0.0.1`. Do not override that option, expose the port through a proxy or
tunnel, or add an inbound firewall rule.

## Offline operation and verification

Once dependencies are installed, disconnect Wi-Fi/mobile hotspots and launch
the app with the command above. The browser connection to the UI is local.
The application code has no network-client imports; Streamlit usage-stat
collection is disabled.

Run all tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

The suite covers key derivation/encryption, wrong passwords, tampering,
permutation reproducibility, text and file/image round trips, byte identity,
capacity limits, image quality, SQLite metadata, and offline configuration.
For a machine-level check while the app is running, verify the listener is
`127.0.0.1:8501` and that the Python process has no non-loopback connections.
In PowerShell:

```powershell
Get-NetTCPConnection -State Listen -LocalPort 8501
```

Windows Resource Monitor or Windows Defender Firewall logging can be used to
inspect the process's established connections. This check is an operational
verification; the tests cannot physically disconnect the computer from the
internet for you.

## Usage and limits

1. Select **Hide Information**, choose text/file/image mode, a carrier image,
   and a password. Confirm the password and download the resulting PNG.
2. Select **Extract Information**, upload the stego PNG/BMP, enter the same
   password, then view or download the extracted payload.
3. Use **Image Analysis** to compare original and modified images.
4. Disable or clear local history in **Settings**.

The application accepts carrier images in PNG, BMP, JPEG, or WebP format and
always writes lossless PNG output. JPEG/BMP/WebP input is decoded before
embedding; lossy JPEG encoding may already have removed image details. Stego
images must remain lossless (PNG/BMP) for extraction. Re-encoding, resizing,
cropping, or editing can corrupt the payload.

Limits are 32 MiB for the original payload, 40 megapixels per image, and 64 MiB
per Streamlit upload. Actual capacity is determined by the carrier's RGB
channels after reserving the fixed header and encryption overhead. Large
images/payloads require substantial local memory and processing time.

Extracted data is provided as a browser download; the application does not
write extracted files to a server-side path, so it cannot overwrite existing
files. Filenames are sanitized to a safe single component while retaining
Unicode characters where supported. Uploads and secret data are processed in
memory; Streamlit session widget values may remain in process memory until the
session ends. They are never stored in SQLite.

## Security architecture

### DPLE key processing

1. Generate a new 16-byte salt with the operating system CSPRNG.
2. Derive a 32-byte root key from the password and salt using Scrypt
   (`N=32768`, `r=8`, `p=1`).
3. Use HKDF-SHA-256 with distinct `StegoVault/DPLE/v1/` context labels to derive
   encryption, embedding, and header-authentication keys.

Passwords are required and limited to 1024 UTF-8 bytes. No password is stored
or included in the output.

### Encryption and embedding

1. Frame the payload type, sanitized filename (for file/image payloads), and
   original bytes.
2. Encrypt the frame using AES-256-GCM with a fresh random 12-byte nonce.
   Authentication data binds a fixed application context, format version, and
   salt. The encrypted container includes its version, salt, nonce, ciphertext
   length, ciphertext, and GCM tag.
3. Write a fixed versioned outer header at the start of the RGB channel LSB
   stream. It contains a magic value, version, salt, and encrypted-container
   length, plus an HMAC-SHA-256 tag derived from the independent header key.
   These fields reveal format and approximate payload size, not message text.
4. Select remaining RGB LSB positions in a reproducible keyed order using an
   eight-round AES-based Feistel permutation and cycle walking to fit the
   carrier's exact position count. This permutation selects locations only; it
   is not used as a data-encryption cipher.
5. Save the modified pixels to PNG. Lossy output would not preserve LSB data.

Extraction validates image dimensions and the authenticated outer header,
reconstructs the same channel order, verifies AES-GCM authentication, and only
then parses the payload frame. A wrong password or modified payload is rejected.
Header integrity is checked before trusting the declared payload length.

This design does not hide the existence of an embedded payload from all
statistical analysis. The basic LSB technique may be detectable; do not use it
to evade monitoring or treat it as deniable communication. For high-assurance
use, have the implementation independently reviewed and test it on the target
environment.

## Project layout

- `app.py`, `.streamlit/config.toml`: local Streamlit entry point/configuration
- `core/`: KDF interface, AES-GCM, payload framing, keyed pixel order, encoder,
  and decoder
- `security/`: password, header integrity, and input validation
- `analysis/`: PSNR, SSIM, dimensions, file sizes, and capacity
- `database/`: optional metadata-only SQLite history
- `ui/`: dashboard, hide, extract, analysis, security, and settings pages
- `tests/`: automated unit, integration, and offline-configuration checks
- `uploads/`, `outputs/`, `data/`: local runtime storage; user payloads are not
  written here by the application
