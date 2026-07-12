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
3. Captures and decrypts a TX-off no-finger reference and live fingerprint images
4. Subtracts the TX-off reference, normalizes the live capture, and extracts **SIGFM** features
5. Matches using **SIGFM** (SIFT-based fingerprint matching via OpenCV)

Fingerprint matching uses SIFT keypoints with CLAHE preprocessing, Lowe's ratio test, mutual nearest-neighbor filtering, and pairwise geometric verification. The driver uses this SIGFM path instead of libfprint's usual minutiae matcher for the small 108x88 captures.

The current preprocessing pipeline is shown below:

<img src="images/goodix53x5-preprocessing-pipeline.png?v=20260610" alt="Goodix 53x5 preprocessing pipeline" width="1000">

## Dependencies

- **libfprint** source tree (tested with v1.94.10)
- **OpenCV 4** (`opencv_core`, `opencv_features2d`, `opencv_flann`, `opencv_imgproc`)
- **OpenSSL 3.0+**
- Standard libfprint build dependencies: Meson, Ninja, pkg-config, GLib, and libgusb

### Build Packages

**Arch Linux:**
```
sudo pacman -S --needed git base-devel meson ninja pkgconf glib2 libgusb opencv openssl fprintd
```

**Fedora:**
```
sudo dnf install git gcc gcc-c++ meson ninja-build pkgconf-pkg-config glib2-devel libgusb-devel opencv-devel openssl-devel fprintd
```

**Ubuntu/Debian:**
```
sudo apt install git build-essential meson ninja-build pkg-config libglib2.0-dev libgusb-dev libopencv-dev libssl-dev fprintd
```

The minimal build command below disables libfprint's generated udev rules and hwdb install, so Debian/Ubuntu users should not need the `udev.pc` build dependency. If you enable udev rules/hwdb or build libfprint's default driver set, Debian 13 provides `udev.pc` in `systemd-dev`.

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

meson setup builddir \
  --prefix=/usr \
  -Ddrivers=goodix53x5 \
  -Dudev_hwdb=disabled \
  -Dudev_rules=disabled \
  -Dintrospection=false \
  -Dinstalled-tests=false \
  -Ddoc=false
ninja -C builddir
sudo ninja -C builddir install
sudo systemctl restart fprintd
```

`-Ddrivers=goodix53x5` avoids building unrelated libfprint drivers and their dependencies. `-Dudev_hwdb=disabled -Dudev_rules=disabled` avoids requiring `udev.pc`; the Goodix 53x5 driver itself is a USB/libgusb driver and does not use udev APIs.

Use `--prefix=/usr` so the installed libfprint replaces the system library used by `fprintd`. A default Meson setup may install into `/usr/local`, which `fprintd` may not load.

### Updating

If you already installed this driver, update this repository, copy the newer driver files into libfprint, then rebuild libfprint:

```bash
cd /path/to/goodix53x5-libfprint
git pull
./install.sh /path/to/libfprint

cd /path/to/libfprint/builddir
meson setup --reconfigure .. \
  --prefix=/usr \
  -Ddrivers=goodix53x5 \
  -Dudev_hwdb=disabled \
  -Dudev_rules=disabled \
  -Dintrospection=false \
  -Dinstalled-tests=false \
  -Ddoc=false
ninja
sudo ninja install
sudo systemctl restart fprintd
```

If `install.sh` cannot apply the Meson integration patch automatically, it prints the manual edits needed for that libfprint tree.

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
         [ 'drivers/goodix53x5/goodix53x5.c', 'drivers/goodix53x5/goodix53x5-proto.c', 'drivers/goodix53x5/goodix53x5-crypto.c', 'drivers/goodix53x5/goodix53x5-transport.c', 'drivers/goodix53x5/goodix53x5-commands.c', 'drivers/goodix53x5/goodix53x5-session.c', 'drivers/goodix53x5/goodix53x5-scan.c', 'drivers/goodix53x5/goodix53x5-enroll.c', 'drivers/goodix53x5/goodix53x5-auth.c', 'drivers/goodix53x5/goodix53x5-match.c', 'drivers/goodix53x5/goodix53x5-calibration.c', 'drivers/goodix53x5/goodix53x5-image.c' ],
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

- **TX-off preprocessing** subtracts a no-finger reference frame from each live 12-bit capture, then normalizes the unclipped interior pixels using the 3%..97% percentile range.
- **Clipped non-contact areas** at raw value `4095` are excluded from normalization and filled from the unclipped interior's 99th-percentile residual. This renders non-contact regions flat white instead of preserving the inverted reference grid.
- **Enrollment coverage** rejects samples with more than 10% clipped/non-contact pixels and asks for another touch, so stored templates keep useful ridge coverage.
- **SIGFM matching** uses OpenCV SIFT features with CLAHE contrast enhancement, Lowe's ratio test, mutual nearest-neighbor filtering, and pairwise geometric verification. Verify/identify accept a print when the best enrolled-sample score is `>= 150` (`GOODIX_SIGFM_BEST_MIN`).
- **8 enrollment samples** are stored as serialized SIGFM feature templates, not raw or processed images. If you enrolled with an older preprocessing/template format, re-enroll your fingers after installing this version.

## Matching accuracy and security

This is a small (108x88 px) press sensor with SIFT-based matching, so treat it as **convenience-grade** authentication rather than a high-security factor.

An earlier version of this driver could accept non-enrolled fingers ([issue #3](https://github.com/AndyHazz/goodix53x5-libfprint/issues/3)). That was traced to the image preprocessing, not the matcher: the current TX-off reference subtraction and clipped-area whitening produce much cleaner ridge detail, which separates genuine and impostor captures well. In on-device testing after this change, enrolled fingers scored well above the accept gate while non-enrolled fingers scored at or near zero.

The accept gate is `GOODIX_SIGFM_BEST_MIN` in `goodix53x5.h` (default `150`). Raising it makes acceptance stricter - fewer false accepts at the cost of more re-presses of a genuine finger; lowering it does the reverse. The default suits typical day-to-day login on this sensor; tune it to taste.

## File Structure

```
drivers/goodix53x5/
  goodix53x5.h              - Public driver type declaration
  goodix53x5.c              - libfprint entry points: ID table, class init, vfuncs
  goodix53x5-private.h      - Private device state and shared driver constants
  goodix53x5-transport.c/.h - USB I/O, chunked send/receive, command sub-SSM
  goodix53x5-commands.c/.h  - Named device commands and reply parsers
  goodix53x5-session.c/.h   - Open/initialization SSM, reinit after sleep, suspend/resume
  goodix53x5-scan.c/.h      - FDT finger detection and image capture SSMs
  goodix53x5-enroll.c/.h    - Enrollment SSM and template assembly
  goodix53x5-auth.c/.h      - Verify/identify SSM and result reporting
  goodix53x5-match.c/.h     - SIGFM template format, serialization, scoring
  goodix53x5-calibration.c/.h - OTP parsing, config patching, FDT base math
  goodix53x5-image.c/.h     - Raw12 decode, TX-off subtraction, normalization
  goodix53x5-proto.c/.h     - Wire protocol: message building, reassembly, parsing
  goodix53x5-crypto.c/.h    - Crypto: GTLS, AES, HMAC, CRC, GEA decryption

sigfm/
  sigfm.hpp              - SIGFM C API header
  sigfm.cpp              - SIFT feature extraction and matching (with CLAHE)
  binary.hpp             - Binary serialization for print storage
  img-info.hpp           - SigfmImgInfo struct (keypoints + descriptors)

images/
  goodix53x5-preprocessing-pipeline.png - Preprocessing pipeline visualization
```

## Credits

- SIGFM matching library from [goodix-fp-linux-dev/sigfm](https://github.com/goodix-fp-linux-dev/sigfm), by Matthieu Charette, Natasha England-Elbro, and Timur Mangliev
- Protocol reverse-engineering from [goodix-fp-linux-dev](https://github.com/goodix-fp-linux-dev)

## License

LGPL-2.1-or-later (same as libfprint)
