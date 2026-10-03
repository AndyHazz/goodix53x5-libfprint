# Packaging And Releases

Releases are GitHub releases built by `.github/workflows/release.yml`. Each one
carries:

| Asset | Contents |
| --- | --- |
| `goodix53x5-libfprint-VERSION.tar.xz` | Complete source: this repository plus the pinned libfprint and fprintd checkouts |
| `fprintd-goodix53x5_VERSION-1.DISTRO_amd64.deb` | Ubuntu 22.04, 24.04 and 26.04, Debian 12 and 13 (the package version inside is `VERSION-1~DISTRO`) |
| `fprintd-goodix53x5-VERSION-1.fcNN.x86_64.rpm` | Fedora 43 and 44 |
| `libfprint-goodix53x5-aur-VERSION.tar.gz` | `PKGBUILD`, `.SRCINFO` and install script for the `libfprint-goodix53x5` AUR package |
| `SHA256SUMS` | Checksums of every asset, also covered by GitHub build provenance attestations |

Other distributions use the source installation. The release notes tell those
users to clone the release tag or extract the release source archive
and run `./install.sh`, and not to use GitHub's automatically generated source
archives, which lack the pinned sources and `release.env`.

## Packages

Both formats build one package, `fprintd-goodix53x5`, from the
`goodix53x5-libfprint` source:

- libfprint with only the `goodix53x5` driver, in the private directory
  `<libdir>/libfprint-goodix53x5`. It has no development files and never
  replaces the distribution's libfprint.
- The patched fprintd at the distribution's normal paths: daemon, `fprintd-*`
  commands, PAM module, systemd unit, D-Bus and polkit files, and the Milan
  udev rule. The daemon loads the private libfprint through its `RUNPATH`.

The 1.0.0 test release from seaweeduk/goodix53x5-libfprint shipped the
private libfprint as a separate `libfprint-goodix53x5` deb/rpm package. Current
packages take it over (`Breaks` and `Replaces` on Debian and Ubuntu,
`Obsoletes` on Fedora), so upgrading removes it in the same transaction.

`fprintd-goodix53x5` replaces the distribution's fprintd packages, which the
package manager removes during installation:

| | Debian and Ubuntu | Fedora |
| --- | --- | --- |
| Satisfies dependencies on | `fprintd`, `libpam-fprintd` (`Provides`, version 1.94.5) | `fprintd`, `fprintd-pam`, `fprintd-devel` (`Provides`, version 1.94.5) |
| Removes | `fprintd`, `libpam-fprintd` (`Conflicts` and `Replaces`) | `fprintd`, `fprintd-pam`, `fprintd-devel` below 1.95 (`Obsoletes`) |
| Fingerprint login | Ships the distribution's `pam-auth-update` profile, disabled by default and unregistered on removal | Uses authselect's `with-fingerprint` feature, disabled on removal |

The distribution's libfprint stays installed but unused: only the fprintd
daemon links libfprint, and it resolves the private copy first. The packaged
fprintd needs libfprint symbols that only the patched build provides, so it
cannot start against the distribution's library by mistake.

The package scripts refuse to install over a source installation (an existing
`/usr/share/goodix53x5-milan/inventory.json`, or the older
`/opt/goodix53x5-milan` layout and its fprintd drop-in). On installation they
reload udev, re-apply the Milan rule to an attached sensor, and restart fprintd
so the sensor is opened immediately. Print state in `/var/lib/fprint` is never
removed.

## Arch Linux (AUR)

The `libfprint-goodix53x5` AUR package builds the same payload as the Debian and
Fedora packages from the release source archive, which its `PKGBUILD` downloads
from the GitHub release and checks by SHA-256. The package keeps its historical
name so existing AUR installations upgrade in place:

- `epoch=1`, so release versions sort above the old `1.94.10-N` libfprint-based
  versions.
- `provides=fprintd=1.94.5` and `conflicts=fprintd`: pacman offers to remove
  the distribution's fprintd. The distribution's libfprint may stay installed;
  the private copy lives in `/usr/lib/libfprint-goodix53x5`.
- The install script reloads udev, restarts fprintd when a supported sensor is
  attached, and on upgrade from the sigfm driver asks users to re-enroll.
  Fingerprint login is left to the user's PAM configuration.

The template and its install script are in `arch/`.
`arch/make-aur-package.sh ARCHIVE OWNER/REPOSITORY DIR` fills in the version,
download URL and checksum, and writes `.SRCINFO`; it needs `makepkg`. The
workflow builds the package from the generated files in an Arch container and
attaches them to the release.

Publishing a release runs `.github/workflows/aur.yml`, which pushes the
release's AUR files to `aur.archlinux.org` when the repository has an
`AUR_SSH_PRIVATE_KEY` secret. To set that up once, create a key for it, add the
public half to the AUR account that maintains the package (My Account, SSH
Public Key; the field accepts one key per line), and store the private half:

```sh
ssh-keygen -t ed25519 -N '' -C 'goodix53x5-libfprint releases' -f aur-release
gh secret set AUR_SSH_PRIVATE_KEY < aur-release
rm aur-release
```

The workflow can also be run from the Actions tab for an already published
release. Without the secret it does nothing, and the maintainer pushes the
files with:

```sh
GH_REPO=OWNER/REPOSITORY packaging/arch/update-aur.sh VERSION
```

Both download the release's AUR bundle and check it against `SHA256SUMS`. The
script shows the change and asks before pushing.

## Build Pipeline

1. `make-source-archive.sh VERSION DIR` archives `HEAD` and fetches the pinned
   libfprint and fprintd revisions as shallow checkouts under `sources/`. The
   archive records its version, revision and commit time in `release.env`.
   Tracked files must be committed.
2. `build-package.sh [--install-deps] ARCHIVE DIR` extracts the archive and
   builds the host distribution's packages with `dpkg-buildpackage` or
   `rpmbuild`. `--install-deps` installs the build dependencies as root.
   Package changelogs are dated from the release commit.
3. Both `debian/rules` and the RPM spec run
   `scripts/build-milan-stack-local.sh --package-root DIR`. This is the same
   builder as the source installation: it verifies the pinned sources and patch
   digests, applies the overlays, runs the libfprint and Milan test suites, and
   stages a release payload. The package layout only moves libfprint into its
   private directory, links the daemon to it, and drops libfprint's
   development files.

Pull requests that change packaging, patches or the stack builder build every
package, including the AUR package, through `.github/workflows/packages.yml`.

### Building Locally

With podman or docker, build any target from a committed checkout:

```sh
packaging/make-source-archive.sh 0.0.0~dev dist
podman run --rm -v "$PWD:/src" -w /src docker.io/library/ubuntu:24.04 \
  packaging/build-package.sh --install-deps dist/goodix53x5-libfprint-0.0.0~dev.tar.xz dist/out
```

Replace the image with `ubuntu:22.04`, `ubuntu:26.04`, `debian:12`,
`debian:13`, `fedora:43` or `fedora:44`. Build output stays under
`.build/packages`.

## Releasing

Releases are made from `main`:

```sh
packaging/release.sh patch        # or minor, major, or an exact version such as 1.1.0
```

This starts the Release workflow (also available from the Actions tab). It:

1. selects the version from the latest `vX.Y.Z` tag, refusing anything that is
   not newer. Without any tag, `patch`, `minor` and `major` all give `1.0.0`,
   so give the first release an exact version newer than the test packages
   seaweeduk/goodix53x5-libfprint published (up to `1.0.2`), such as
   `packaging/release.sh 1.1.0`, so those installations upgrade;
2. builds the source archive, all seven targets and the AUR package;
3. writes `SHA256SUMS` and build provenance attestations;
4. creates a **draft** release targeting the built commit, with notes generated
   from the pull requests merged since the previous release first, followed by
   the install instructions from `packaging/release-notes.md` (filled in with
   the tag and repository).

Review the draft on the releases page, edit the notes (add highlights and any
re-enrollment warnings), and publish it. Publishing creates the tag; nothing is
public before then. Publishing also updates the AUR package; see
[Arch Linux (AUR)](#arch-linux-aur). Package changelogs link to the release
notes rather than duplicating them.

### Versions

The tag is the only version source; no file is bumped.

- **Patch**: fixes and packaging-only changes.
- **Minor**: new behaviour or supported sensors, and compatible updates of the
  pinned libfprint or fprintd.
- **Major**: changes that require re-enrollment or break compatibility with the
  distribution's fprintd clients.

Package revisions stay at `-1`; a packaging fix is a new patch release. Source
installations record the version from `git describe` or `release.env` in
`/usr/share/goodix53x5-milan/build.env`.

### Release Notes

Notes list pull request titles, grouped by label (`.github/release.yml`). Give
every pull request a user-facing title and exactly one type label; add
`breaking` as well when users must act. A pull request appears in the first
matching section.

| Label | Section | Use for |
| --- | --- | --- |
| `breaking` | ⚠️ Action required | Added to a type label when users must re-enroll, migrate or change configuration; implies a major release |
| `feature` | New features | New user-visible capability |
| `matching` | Recognition and Windows parity | Capture, matching, learning or anti-spoofing behaviour |
| `fix` | Fixes | User-visible bugs, reliability, sleep/resume or sensor recovery |
| `performance` | Performance | Faster unlocks, startup or matching |
| `security` | Security | Hardening of the encrypted link, keys or stored data |
| `hardware` | Hardware support | New or newly validated sensors and laptops |
| `packaging` | Packaging and installation | Packages, installers and supported distributions |
| `skip-notes` | Left out of the notes | Refactors, tests, parity tooling, CI, docs and RE notes |

Unlabelled pull requests appear under "Other changes". A new label needs a
matching category in `.github/release.yml`. Create the labels once, before
the first release that has a previous tag to compare against (re-running is
harmless):

```sh
for label in breaking feature matching fix performance security hardware packaging skip-notes; do
  GH_REPO=AndyHazz/goodix53x5-libfprint gh label create "$label" --force
done
```
