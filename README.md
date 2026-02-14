# Goodix HTK32 (27c6:5385) libfprint Driver

A libfprint driver for the Goodix HTK32 fingerprint sensor found in the **Dell XPS 13 7390** and possibly other laptops using the `27c6:5385` USB device.

## Hardware

- **Vendor ID:** `0x27c6`
- **Product ID:** `0x5385`
- **Sensor:** 108 x 88 pixels, capacitive press-type
- **Known devices:** Dell XPS 13 7390 2-in-1

Check if you have this sensor:
```
lsusb | grep 27c6:5385
```

## How It Works

The sensor provides raw 12-bit capacitive images encrypted with a TLS-like protocol (GTLS). The driver:

1. Initializes the sensor: PSK exchange, GTLS handshake, config upload, FDT calibration
2. Detects finger placement via FDT (Finger Detection Threshold) events
3. Captures and decrypts the fingerprint image
4. Matches using **SIGFM** (SIFT-based fingerprint matching via OpenCV)

Fingerprint matching uses SIFT keypoints with CLAHE preprocessing, Lowe's ratio test, and pairwise geometric verification. This approach works well with the small 108x88 sensor where traditional minutiae-based methods struggle.

## Dependencies

- **libfprint** source tree (tested with v1.94.10)
- **OpenCV 4** (`opencv_core`, `opencv_features2d`, `opencv_flann`, `opencv_imgproc`)
- **OpenSSL 3.0+**
- Standard libfprint build dependencies (meson, ninja, glib, libgusb, etc.)

### Installing OpenCV

**Arch Linux:**
```
sudo pacman -S opencv
```

**Fedora:**
```
sudo dnf install opencv opencv-devel
```

**Ubuntu/Debian:**
```
sudo apt install libopencv-dev
```

## Installation

### Quick Start

```bash
# Clone libfprint
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
cd libfprint

# Apply this driver
/path/to/goodix53x5-driver/install.sh .

# The install script will print manual meson.build edits needed.
# Apply those edits, then:

meson setup builddir
cd builddir
ninja
sudo ninja install
sudo systemctl restart fprintd
```

### Manual Integration

1. Copy `drivers/goodix53x5/` into `libfprint/libfprint/drivers/goodix53x5/`
2. Copy `sigfm/` into `libfprint/libfprint/sigfm/`
3. Edit `libfprint/libfprint/meson.build`:
   - Add to the `driver_sources` dictionary:
     ```meson
     'goodix53x5' :
         [ 'drivers/goodix53x5/goodix53x5.c', 'drivers/goodix53x5/goodix53x5-proto.c', 'drivers/goodix53x5/goodix53x5-crypto.c', 'drivers/goodix53x5/goodix53x5-device.c' ],
     ```
   - Add SIGFM static library build (before `libfprint_drivers`):
     ```meson
     opencv_inc = include_directories('/usr/include/opencv4')
     opencv_core = cc.find_library('opencv_core')
     opencv_features2d = cc.find_library('opencv_features2d')
     opencv_flann = cc.find_library('opencv_flann')
     opencv_imgproc = cc.find_library('opencv_imgproc')
     opencv_dep = declare_dependency(
         include_directories: opencv_inc,
         dependencies: [opencv_core, opencv_features2d, opencv_flann, opencv_imgproc],
     )
     libsigfm = static_library('sigfm',
         'sigfm/sigfm.cpp',
         dependencies: [opencv_dep],
         cpp_args: ['-std=c++17'],
         install: false)
     ```
   - Add `libsigfm` to `link_with` for both `libfprint_drivers` and the main `libfprint` library
   - Add `opencv_dep` to the main library `dependencies`
4. Edit root `meson.build`:
   - Add `'goodix53x5'` to the default drivers list
   - Add `'goodix53x5' : [ 'openssl' ]` to `driver_helpers`
5. Reconfigure and build

## Enrollment and Verification

After installation, use your desktop environment's fingerprint settings (GNOME, KDE, etc.) or the command line:

```bash
# Enroll a finger (8 samples required)
fprintd-enroll

# Verify
fprintd-verify
```

## Technical Notes

- **SIGFM matching** uses OpenCV SIFT features with CLAHE contrast enhancement. Score threshold is 5 (correct finger typically scores 28-24000+, wrong finger scores 0-4).
- **8 enrollment samples** are stored as raw 108x88 grayscale images. During verification, SIFT features are extracted from each stored sample and compared with the live capture.
- **Image preprocessing** removes horizontal banding and vertical striping via row/column mean subtraction, then normalizes to 8-bit.
- Thermal throttling is disabled (`temp_hot_seconds = -1`) since the small sensor generates negligible heat.

## File Structure

```
drivers/goodix53x5/
  goodix53x5.h           - Header: defines, structs, function declarations
  goodix53x5.c           - Main driver: SSMs for open, enroll, verify, identify
  goodix53x5-device.c    - Device helpers: OTP, config, FDT, image processing
  goodix53x5-proto.c     - USB protocol: message building, reassembly, parsing
  goodix53x5-crypto.c    - Crypto: GTLS, AES, HMAC, PSK, GEA decryption

sigfm/
  sigfm.hpp              - SIGFM C API header
  sigfm.cpp              - SIFT feature extraction and matching (with CLAHE)
  binary.hpp             - Binary serialization for print storage
  img-info.hpp           - SigfmImgInfo struct (keypoints + descriptors)
```

## Credits

- SIGFM matching library from [goodix-fp-linux-dev/sigfm](https://github.com/goodix-fp-linux-dev/sigfm), by Matthieu Charette, Natasha England-Elbro, and Timur Mangliev
- Protocol reverse-engineering from [goodix-fp-linux-dev](https://github.com/goodix-fp-linux-dev)

## License

LGPL-2.1-or-later (same as libfprint)
