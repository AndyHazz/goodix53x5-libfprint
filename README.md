# Goodix 53x5 libfprint Driver

**A native Linux implementation of Goodix's Windows Milan biometric stack,
reverse-engineered and validated byte for byte.**

This out-of-tree libfprint driver supports Goodix HTK32 USB fingerprint sensors
with IDs `27c6:5335`, `27c6:5385`, and `27c6:5395`. It implements the sensor
protocol, image processing, enrollment, matching, anti-fake processing, and
adaptive template updates without requiring Windows or proprietary Goodix
binaries at runtime.

> [!IMPORTANT]
> The Milan driver was developed with AI assistance. The implementation is
> tested against the native Windows Milan behavior with deterministic,
> byte-level parity checks; generated code is not treated as evidence of
> correctness by itself.

## Supported Hardware

| Laptop | Sensor |
| --- | --- |
| Dell XPS 13 9305 | `27c6:5335` |
| Dell XPS 13 7390 2-in-1 | `27c6:5385` |
| Dell XPS 15 9570 | `27c6:5395` |
| Dell XPS 15 7590 | `27c6:5395` |

Other laptops with one of these sensor IDs should work too. Check yours with
`lsusb -d 27c6:`.

Before installing on an unlisted Goodix USB device, run:

```sh
sudo ./scripts/goodix53x5-detect.sh
```

If it reports `COMPATIBLE CANDIDATE`, either:

- [Open a compatibility issue](https://github.com/AndyHazz/goodix53x5-libfprint/issues/new)
  with its output, your laptop model, and Linux distribution; or
- Submit a PR adding the ID, with probe and hardware-test results, to:
  - `drivers/goodix53x5/goodix53x5.c` (driver ID table)
  - `meson-integration.patch` (hwdb supported/unsupported blocks and the
    `fprint-list-udev-hwdb.c` allowlist)
  - `udev/99-goodix53x5-milan-persist.rules` (USB persistence across
    hibernation)
  - `scripts/goodix53x5-detect.c` (detector's supported-ID check)

## How Milan Works

The sensor sends encrypted 108 x 88, 12-bit capacitive images over USB. Milan
turns those small captures into a fingerprint template that can improve after
successful matches.

<img src="images/milan-driver/01-capture.png" alt="Empty sensor references and a raw fingerprint capture becoming a clear processed image" width="800">

**Capture and reveal.** Empty reference frames describe the sensor itself.
Milan uses that baseline to remove the sensor background, expose ridge detail,
check the image, and extract a compact fingerprint representation.

<img src="images/milan-driver/02-enroll.png" alt="Accepted fingerprint touches being combined into a Milan template" width="800">

**Build the first template.** Enrollment collects twelve accepted touches.
Different positions and pressure reveal different parts of the finger; weak or
repetitive captures are retried. The resulting template stores extracted
features and their relationships, not a gallery of fingerprint photographs.

<img src="images/milan-driver/03-study.png" alt="A new fingerprint touch being matched and, after success, used to improve the saved template" width="800">

**Recognize and improve.** A new touch is checked against the enrolled
template. Rejected scans never teach the system. After a confirmed match, Milan
can retain useful new variation and save the improved template for future
unlocks. The template has a fixed capacity, so new evidence is appended while
space remains and can replace existing evidence once it is full.

> [!NOTE]
> On the same challenging dataset, Milan's adaptive learning raised the
> genuine-accept rate from roughly **82.5-85% before learning** to **98.5% and
> 99% in learned runs**, with **zero false accepts** in those runs. This indicates
> that template study and updates contribute significantly over time. These are
> project experiments, not certification results or guarantees for other
> hardware and datasets.

Under the hood, the driver initializes the sensor and its GTLS session,
calibrates finger detection, runs Milan preprocessing and anti-fake checks,
extracts and relates features, performs matching and study, then stores the
result through libfprint. Successful learning updates are persisted by the
paired fprintd build.

The Milan implementation was reconstructed from the native Windows behavior.
The reference DLL is used only as a private interoperability oracle and is not
included in, discovered by, or required to run this repository.

## Install

Every install method provides pinned, patched libfprint `v1.94.10` and fprintd
`v1.94.5`, including the fprintd commands, PAM module, and systemd/D-Bus
integration. Each replaces your distribution's fprintd, so other fingerprint
readers are not supported while it is installed.

Fingerprints enrolled with the older sigfm-based driver are not compatible.
When upgrading from it, delete them and enroll again:

```sh
sudo fprintd-delete "$USER"
```

If you installed the sigfm driver by building libfprint yourself and running
`sudo ninja install`, undo that build first. Otherwise the source installer
refuses to overwrite its files, and with the packages the old library is left
behind in place of your distribution's:

```sh
sudo ninja -C /path/to/libfprint/builddir uninstall
```

Then reinstall your distribution's libfprint package to restore the files that
build replaced (`sudo pacman -S libfprint`, `sudo apt install --reinstall
libfprint-2-2` or `sudo dnf reinstall libfprint`). If the build directory is
gone, reinstalling the package is enough. Users of the old AUR package can
simply upgrade it.

> [!WARNING]
> Hyprlock 0.9.6 can record successful fingerprint unlocks as PAM failures and
> leave fingerprint authentication unavailable after a rapid relock, potentially
> causing `pam_faillock` lockouts. Use Hyprlock 0.9.5 until
> [hyprwm/hyprlock#1074](https://github.com/hyprwm/hyprlock/issues/1074) is
> resolved.

### Arch Linux (AUR)

```sh
yay -S libfprint-goodix53x5
```

The AUR package is built from each release. pacman offers to remove the
distribution's `fprintd`, which the package replaces; accept it. The driver's
libfprint is kept in a private directory, so the distribution's libfprint can
stay installed. Fingerprint login is not enabled automatically; add
`pam_fprintd.so` to the PAM services you want, as described in the
[Arch Wiki](https://wiki.archlinux.org/title/Fprint#Configuration).

Update with your AUR helper as usual. To return to the distribution's fprintd:

```sh
sudo pacman -R libfprint-goodix53x5
sudo pacman -S fprintd
```

### Packages: Ubuntu, Debian, Fedora

Each [release](https://github.com/AndyHazz/goodix53x5-libfprint/releases)
has one x86-64 package for each of Ubuntu 22.04, 24.04 and 26.04, Debian 12
and 13, and Fedora 43 and 44; the release notes link each one directly.
Distributions based on one of these may work with the package for their base
release, but they are not tested. Download the package for your distribution
and install it:

```sh
sudo apt install ./fprintd-goodix53x5_*.deb      # Ubuntu and Debian
sudo dnf install ./fprintd-goodix53x5-*.rpm      # Fedora
```

`fprintd-goodix53x5` replaces the distribution's `fprintd` and its PAM module
(`libpam-fprintd` or `fprintd-pam`); the package manager removes them during
the installation. The driver's libfprint is kept in a private directory used
only by this fprintd, so the distribution's libfprint stays installed and
untouched.

Fingerprint login starts disabled. Enable it with:

```sh
sudo pam-auth-update --enable fprintd            # Ubuntu and Debian
sudo authselect enable-feature with-fingerprint  # Fedora
```

Update by installing a newer release's package the same way. To remove the
package and return to the distribution's fprintd:

```sh
# Ubuntu and Debian
sudo apt remove fprintd-goodix53x5
sudo apt install fprintd libpam-fprintd
# Fedora
sudo dnf remove fprintd-goodix53x5
sudo dnf install fprintd fprintd-pam
```

Prints in `/var/lib/fprint` are kept in both directions. The package refuses to
install over a source installation; run `./uninstall.sh` from that checkout
first.

### Source Installation: Other Distributions

The source installation builds the same stack and installs it into your
distribution's normal paths under `/usr`. Remove your distribution's libfprint
and fprintd packages first. The installer refuses to overwrite package-owned or
otherwise unrecorded files.

To install a specific release, clone its tag, or extract that release's
`goodix53x5-libfprint-VERSION.tar.xz`, which also contains the pinned libfprint
and fprintd sources and builds offline:

```sh
git clone --branch vX.Y.Z https://github.com/AndyHazz/goodix53x5-libfprint
cd goodix53x5-libfprint
./install.sh
```

GitHub's automatically generated "Source code" archives on the releases page
lack those pinned sources and the release version; use the clone or the release
archive instead.

Print state stays in `/var/lib/fprint`. The installer does not enable
fingerprint authentication in PAM; configure that through your distribution.

Build dependencies include a C toolchain, Git, Meson, Ninja, pkg-config,
GLib/GIO, GUsb, OpenSSL 3, libdeflate, Python 3, gettext, Perl's `pod2man`, and
the development dependencies of libfprint and fprintd, including Polkit's
GObject library, PAM, and libsystemd. On Arch, GLib's build tools such as
`glib-mkenums` are in `glib2-devel`:

```sh
sudo pacman -S --needed base-devel git glib2-devel libdeflate libgusb meson \
  ninja openssl pam polkit python systemd
```

To update, check out the desired release tag or revision and run
`./install.sh` again. For layout, build controls, status checks, and removal
behaviour, see the
[Milan stack guide](scripts/MILAN-STACK.md).

## Enroll And Verify

Use your desktop environment's fingerprint settings or fprintd directly:

```sh
fprintd-enroll
fprintd-verify
```

> [!TIP]
> Fingerprint recognition should improve with regular use. After the 12
> enrollment scans, the driver continues learning from successful unlocks,
> adapting to different angles, positions, pressure, and finger conditions.
> Failed scans are never learned.

## Windows Dual Boot

Normal Linux-only installations retain the automatic all-zero PSK setup. An
optional Windows key file enables shared-key operation without changing the
default path. See the [Windows dual-boot migration guide](WINDOWS-DUAL-BOOT.md).

## Limitations And Security

- This is an experimental, out-of-tree driver tied to pinned libfprint and
  fprintd revisions.
- Fingerprint images and matching are handled on the host. This is not a
  match-on-chip or secure-element design.
- A plaintext imported GTLS key is protected by filesystem permissions, not a
  TPM or DPAPI. Do not publish it or commit it to a repository.
- A compromised root or kernel environment can bypass authentication or access
  biometric data. Fingerprint unlock should be treated as a convenience factor,
  not the only protection for sensitive data.

## Development

`./install.sh --debug` builds the same driver with GLib debug messages, timing
logs and diagnostic summaries in the `fprintd.service` journal, which helps with
bug reports. Release builds exclude capture writers and parity diagnostics.

The driver's unit and native-fixture tests run in CI. To run them locally:

```sh
GOODIX53X5_DEBUG=0 ./scripts/build-local.sh
meson test -C .build/libfprint/builddir --print-errorlogs \
  goodix53x5-milan-synthetic goodix53x5-milan-state \
  goodix53x5-milan-native-study goodix53x5-milan-native-preprocess \
  goodix53x5-milan-native-match goodix53x5-milan-runtime \
  goodix53x5-milan-transport
```

The Milan driver was developed in
[seaweeduk/goodix53x5-libfprint](https://github.com/seaweeduk/goodix53x5-libfprint),
which keeps the developer tooling that is not part of this repository:

- the Milan parity harness (`tools/milan-parity`), which replays captured
  operations against the native Windows driver and compares the results byte
  for byte;
- the [debug capture guide](https://github.com/seaweeduk/goodix53x5-libfprint/blob/main/DEBUG-CAPTURE-GUIDE.md)
  for collecting private debug data;
- reverse-engineering notes on the native Milan functions, in
  [`re/milan` on the `milan-dev` branch](https://github.com/seaweeduk/goodix53x5-libfprint/tree/milan-dev/re/milan).

Package builds and the release process are described in the
[packaging guide](packaging/README.md).

## Uninstall

For packages, see [Arch Linux (AUR)](#arch-linux-aur) and
[Packages](#packages-ubuntu-debian-fedora). For a source installation:

```sh
./uninstall.sh
```

This removes the files recorded by the installer and leaves saved fingerprints
and the imported Windows PSK under `/var/lib/fprint` in place. Reinstall your
distribution's packages afterwards if you want them.

## Credits

- [AndyHazz](https://github.com/AndyHazz) for the original driver and its
  sensor protocol implementation
- [seaweeduk](https://github.com/seaweeduk) for the Milan driver, reconstructed
  from the native Windows behavior, and its paired fprintd and packaging
- [Berkekbgz](https://github.com/berkekbgz) for reversing the native Chicago
  matcher in [libfprint-goodix-spi](https://github.com/berkekbgz/libfprint-goodix-spi)
  and for his advice
- The SIGFM matching library used by earlier versions, from
  [goodix-fp-linux-dev/sigfm](https://github.com/goodix-fp-linux-dev/sigfm), by
  Matthieu Charette, Natasha England-Elbro, and Timur Mangliev
- Protocol research and earlier Goodix Linux work from
  [goodix-fp-linux-dev](https://github.com/goodix-fp-linux-dev)
- libfprint and fprintd from the
  [freedesktop.org fingerprint stack](https://fprint.freedesktop.org/)

## License

LGPL-2.1-or-later, matching libfprint.
