# Goodix HTK32 (27c6:5335 / 27c6:5385 / 27c6:5395) libfprint Driver

A libfprint driver for the Goodix HTK32 fingerprint sensor found in the **Dell XPS 13 9305**, the **Dell XPS 13 7390**, the **Dell XPS 15 9570** and possibly other laptops using the `27c6:5335`, `27c6:5385` or `27c6:5395` USB device.

## Hardware

- **Vendor ID:** `0x27c6`
- **Product IDs:** `0x5335`, `0x5385`, `0x5395`
- **Sensor:** 108 x 88 pixels, capacitive press-type
- **Known devices:** Dell XPS 13 9305, Dell XPS 13 7390 2-in-1, Dell XPS 15 9570

Check if you have this sensor:
```
lsusb | grep -E '27c6:(5335|5385|5395)'
```

## How It Works

The sensor provides raw 12-bit capacitive images encrypted with a TLS-like protocol (GTLS). The driver:

1. Initializes the sensor: PSK exchange, GTLS handshake, config upload, FDT calibration
2. Detects finger placement via FDT (Finger Detection Threshold) events
3. Captures and decrypts the fingerprint image
4. Matches using **SIGFM** (SIFT-based fingerprint matching via OpenCV)

Fingerprint matching uses SIFT keypoints with CLAHE preprocessing, Lowe's ratio test, and pairwise geometric verification. The driver uses this SIGFM path instead of libfprint's usual minutiae matcher for the small 108x88 captures.

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

### Arch Linux (AUR)

```bash
yay -S libfprint-goodix53x5
sudo pacman -S fprintd
sudo systemctl restart fprintd
```

This builds a patched libfprint with the driver included. No manual steps needed.

### Other Distros: Quick Start

```bash
# Clone libfprint
git clone https://gitlab.freedesktop.org/libfprint/libfprint.git
cd libfprint

# Apply this driver
/path/to/goodix53x5-libfprint/install.sh .

# The install script will print manual meson.build edits needed.
# Apply those edits, then:

meson setup builddir --prefix=/usr -Dinstalled-tests=false -Ddoc=false
ninja -C builddir
sudo ninja -C builddir install
sudo systemctl restart fprintd
```

Use `--prefix=/usr` so the installed libfprint replaces the system library used by `fprintd`. A default Meson setup may install into `/usr/local`, which `fprintd` may not load.

### Updating

If you already installed this driver, update this repository, copy the newer driver files into libfprint, then rebuild libfprint:

```bash
cd /path/to/goodix53x5-libfprint
git pull
./install.sh /path/to/libfprint

cd /path/to/libfprint/builddir
meson setup --reconfigure .. --prefix=/usr -Dinstalled-tests=false -Ddoc=false
ninja
sudo ninja install
sudo systemctl restart fprintd
```

You usually do not need to repeat the manual Meson edits after the first install.

## Troubleshooting

### Uninstalling

To remove the copied driver files from a libfprint source tree:

```bash
/path/to/goodix53x5-libfprint/uninstall.sh /path/to/libfprint
```

The uninstall script removes `libfprint/drivers/goodix53x5/` and `libfprint/sigfm/`. It will print the manual Meson cleanup steps needed to remove the driver registration, SIGFM/OpenCV build block, and helper mapping.

Preview the removals without deleting files:

```bash
/path/to/goodix53x5-libfprint/uninstall.sh --dry-run /path/to/libfprint
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

## Development

### Local Build

For development, build libfprint with this driver inside this repository:

```bash
./scripts/build-local.sh
```

This clones/prepares libfprint under `.build/libfprint`, copies the current driver and `sigfm` sources into that tree, applies `meson-integration.patch`, and runs `ninja`. Override the libfprint ref with `GOODIX_LIBFPRINT_REF`, for example:

```bash
GOODIX_LIBFPRINT_REF=v1.94.10 ./scripts/build-local.sh
```

## Enrollment and Verification

After installation, use your desktop environment's fingerprint settings (GNOME, KDE, etc.) or the command line:

```bash
# Enroll a finger (8 samples required)
fprintd-enroll

# Verify
fprintd-verify
```

## Troubleshooting

### Capturing debug logs

To gather logs for a bug report, stop the system `fprintd` and run it in the
foreground with debug logging:

```bash
sudo systemctl stop fprintd
sudo G_MESSAGES_DEBUG=all /usr/libexec/fprintd -t
# in another terminal:
fprintd-enroll
```

(The `fprintd` binary path may be `/usr/lib/fprintd/fprintd` on some distros.)

## Technical Notes

- **SIGFM matching** uses OpenCV SIFT features with CLAHE contrast enhancement, Lowe's ratio test, and pairwise geometric scoring. Verify/identify accept a print when the best enrolled-sample score is `>= 14` (`GOODIX_SIGFM_BEST_MIN`).
- **8 enrollment samples** are stored as processed 108x88 8-bit images. During verification, SIFT features are extracted from each stored sample and compared with the live capture.
- **Image preprocessing** uses a row/column bandpass: it removes row/column mean structure, subtracts a wide Gaussian lowpass, applies light smoothing, then normalizes to 8-bit.

## Matching accuracy and security

This is a small (108x88 px) press sensor with SIFT-based matching, so treat it as **convenience-grade** authentication rather than a high-security factor.

An earlier version of this driver could accept non-enrolled fingers ([issue #3](https://github.com/AndyHazz/goodix53x5-libfprint/issues/3)). That was traced to the image preprocessing, not the matcher: the current row/column bandpass front-end produces much cleaner ridge detail, which separates genuine and impostor captures well. In on-device testing after this change, enrolled fingers scored well above the accept gate while non-enrolled fingers scored at or near zero.

The accept gate is `GOODIX_SIGFM_BEST_MIN` in `goodix53x5.h` (default `14`). Raising it makes acceptance stricter - fewer false accepts at the cost of more re-presses of a genuine finger; lowering it does the reverse. The default suits typical day-to-day login on this sensor; tune it to taste.

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
