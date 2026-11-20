## Check your sensor first

List Goodix USB devices with `lsusb` (from `usbutils`):

```sh
lsusb -d 27c6:
```

| Result | What to do |
| --- | --- |
| `27c6:5335`, `27c6:5385` or `27c6:5395` | Supported by this release; choose a download below. Known laptops: Dell XPS 13 9305 (`27c6:5335`), XPS 13 7390 2-in-1 (`27c6:5385`), XPS 15 9570 and XPS 15 7590 (`27c6:5395`). |
| Another `27c6:` Goodix ID | Not supported by this release yet. Run the detector below and report the result. |
| No output | No Goodix USB fingerprint sensor was found; this release does not support your reader. |

The detector talks to the sensor directly, so it needs root and a C compiler with the GUsb development files (`gcc pkg-config libgusb-dev` on Debian and Ubuntu, `gcc pkgconf-pkg-config libgusb-devel` on Fedora, `gcc pkgconf libgusb` on Arch):

```sh
git clone --branch @TAG@ https://github.com/@REPOSITORY@
cd goodix53x5-libfprint
sudo ./scripts/goodix53x5-detect.sh
```

If it reports `COMPATIBLE CANDIDATE`, [open a compatibility issue](https://github.com/@REPOSITORY@/issues/new) with its output, your laptop model and your Linux distribution.

## Which download do I need?

Download the one package for your distribution:

| Distribution | Package |
| --- | --- |
| Ubuntu 26.04 | [fprintd-goodix53x5_@VERSION@-1.ubuntu26.04_amd64.deb](https://github.com/@REPOSITORY@/releases/download/@TAG@/fprintd-goodix53x5_@VERSION@-1.ubuntu26.04_amd64.deb) |
| Ubuntu 24.04 | [fprintd-goodix53x5_@VERSION@-1.ubuntu24.04_amd64.deb](https://github.com/@REPOSITORY@/releases/download/@TAG@/fprintd-goodix53x5_@VERSION@-1.ubuntu24.04_amd64.deb) |
| Ubuntu 22.04 | [fprintd-goodix53x5_@VERSION@-1.ubuntu22.04_amd64.deb](https://github.com/@REPOSITORY@/releases/download/@TAG@/fprintd-goodix53x5_@VERSION@-1.ubuntu22.04_amd64.deb) |
| Debian 13 | [fprintd-goodix53x5_@VERSION@-1.debian13_amd64.deb](https://github.com/@REPOSITORY@/releases/download/@TAG@/fprintd-goodix53x5_@VERSION@-1.debian13_amd64.deb) |
| Debian 12 | [fprintd-goodix53x5_@VERSION@-1.debian12_amd64.deb](https://github.com/@REPOSITORY@/releases/download/@TAG@/fprintd-goodix53x5_@VERSION@-1.debian12_amd64.deb) |
| Fedora 44 | [fprintd-goodix53x5-@VERSION@-1.fc44.x86_64.rpm](https://github.com/@REPOSITORY@/releases/download/@TAG@/fprintd-goodix53x5-@VERSION@-1.fc44.x86_64.rpm) |
| Fedora 43 | [fprintd-goodix53x5-@VERSION@-1.fc43.x86_64.rpm](https://github.com/@REPOSITORY@/releases/download/@TAG@/fprintd-goodix53x5-@VERSION@-1.fc43.x86_64.rpm) |
| Arch Linux | The `libfprint-goodix53x5` AUR package (below) |
| Other distributions | Build this release from source (below) |

Then install it from the download folder:

```sh
sudo apt install ./fprintd-goodix53x5_*.deb   # Ubuntu and Debian
sudo dnf install ./fprintd-goodix53x5-*.rpm   # Fedora
```

The package replaces the distribution's fprintd and its PAM module. Fingerprint login starts disabled. Upgrading from an earlier package uses the same command; enrolled fingerprints are kept. See the [installation guide](https://github.com/@REPOSITORY@/blob/@TAG@/README.md#install) for enabling fingerprint login and for removal.

### Arch Linux

Install or upgrade the [`libfprint-goodix53x5`](https://aur.archlinux.org/packages/libfprint-goodix53x5) AUR package, for example with `yay -S libfprint-goodix53x5`. The AUR is updated shortly after each release. pacman offers to remove the distribution's fprintd, which the package replaces. When upgrading from the older sigfm-based package, delete your fingerprints with `fprintd-delete "$USER"` and enroll again.

### Other distributions

Build and install this release with the source installer:

```sh
git clone --branch @TAG@ https://github.com/@REPOSITORY@
cd goodix53x5-libfprint
./install.sh
```

Alternatively, extract `goodix53x5-libfprint-@VERSION@.tar.xz` from the assets below and run `./install.sh` inside it; it contains the pinned libfprint and fprintd sources and builds offline. To update later, repeat the same steps with the newer release.

GitHub's automatically generated "Source code" archives lack the pinned sources and release version; do not use them with `./install.sh`.

### Verify downloads

`sha256sum --check --ignore-missing SHA256SUMS` or `gh attestation verify FILE --repo @REPOSITORY@`.
