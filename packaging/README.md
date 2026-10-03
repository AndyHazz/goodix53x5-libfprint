# Debian / Ubuntu packaging

`packaging/build-deb.sh` builds `libfprint-goodix53x5`, a package that gives
`fprintd` a libfprint with the goodix53x5 driver without replacing the
distribution's `libfprint-2-2`. `.github/workflows/deb.yml` builds it for
Ubuntu 24.04, Ubuntu 26.04, Debian 12 and Debian 13 and attaches the `.deb`
files to each `v*` release.

## What the package installs

| Path | Purpose |
|------|---------|
| `/usr/lib/libfprint-goodix53x5/libfprint-2.so.2*` | upstream libfprint (`LIBFPRINT_REF`, default `v1.94.10`) built with the full default driver set plus `goodix53x5`, the same recipe as the AUR package |
| `/usr/lib/systemd/system/fprintd.service.d/fprintd-goodix53x5.conf` | sets `LD_LIBRARY_PATH` for fprintd only, so it loads the library above |
| `/usr/lib/udev/hwdb.d/61-libfprint-goodix53x5-autosuspend.hwdb` | autosuspend entries for 27c6:5335/5385/5395 |

`postinst`/`postrm` reload systemd and restart fprintd. `apt remove
libfprint-goodix53x5` returns the system to stock. fprintd only uses libfprint's
public, versioned API (`LIBFPRINT_2.0.0`), so the distro's fprintd 1.94.x
works unchanged with this library; other libfprint consumers keep using the
distro library.

## Why not replace `libfprint-2-2`

The obvious alternative is the classic PPA workflow: take the distribution's
`libfprint` source package, add the driver as a `debian/patches` entry, bump
the version and upload. It is the idiomatic route for small fixes, but it is a
poor fit here:

- **Version race.** The result is a `libfprint-2-2` with a version such as
  `1:1.94.7+tod1-0ubuntu5~24.04.8+goodix1`. The next Ubuntu stable update
  (`~24.04.9` is already in proposed) sorts higher, apt "upgrades" users back
  to the stock package, and the driver silently disappears until someone
  rebases and re-uploads. Overwriting `/usr/lib` by hand has the same problem.
- **Untested libfprint trees.** This driver is developed against upstream
  v1.94.10 and uses libfprint's private `fpi_*` API. Ubuntu 24.04 ships
  1.94.7 and 26.04 ships 1.95.1, both with Canonical's TOD patches, and
  Debian 12 ships 1.94.5. Every series becomes a separate port and a separate
  way to break.
- **Ubuntu only.** Launchpad builds nothing for Debian. Ubuntu's `fprintd`
  also hard-depends on its TOD-patched `libfprint-2-2`, which a replacement
  package has to satisfy or conflict with.

Keeping the library private and pointing only fprintd at it avoids all three,
at the cost of fprintd running libfprint 1.94.10 for every reader instead of
the distro's version.

## Debian and upstream context

Debian's `debian/patches` mechanism (quilt series, DEP-3 headers) is meant for
small distro-side fixes to a pristine upstream tarball. A driver of this size
with an OpenCV dependency is not something the Debian `libfprint` maintainer
would carry as a patch; the only real path into distributions is upstream
libfprint itself, and there are no plans for that (see issue #23: the OpenCV
dependency and SIFT matching on a 108x88 sensor are the blockers).

A standalone `libfprint-goodix53x5` in the Debian archive is also unlikely:
it embeds a second copy of libfprint (Policy 4.13) and overrides a daemon's
library path. It is a reasonable third-party package, which is what this is.

An Ubuntu-specific option worth exploring later is building the driver as a
TOD module (`libfprint-2-tod1` plugin), which is how Dell's proprietary Goodix
drivers ship on Ubuntu. It would plug into the distro libfprint with no
override, but TOD does not exist on Debian and the `tod-1` API has to match
the driver's `fpi_*` usage.

## Building locally

```bash
./packaging/build-deb.sh --install-deps     # apt installs Build-Depends first
sudo apt install ./dist/libfprint-goodix53x5_*.deb
```

Versions look like `1.94.10+git20260805.309d4c6~ubuntu26.04`: libfprint tag,
driver commit date and hash, and the distribution the binary was built on.

## Publishing through a Launchpad PPA

The same package can be served from a PPA so Ubuntu users get it with
`add-apt-repository` and automatic updates. Launchpad builds from a source
package, offline, so the source package carries the libfprint tree with the
driver already integrated (format `3.0 (native)`, about 7 MB). A PPA accepts
each version once, so one source package is generated per series:

```bash
for series in noble resolute; do
    ./packaging/build-deb.sh --source --series "$series"
done
debsign dist/*_source.changes
dput ppa:OWNER/goodix53x5 dist/*_source.changes
```

Users then run:

```bash
sudo add-apt-repository ppa:OWNER/goodix53x5
sudo apt install libfprint-goodix53x5
```

The PPA owner needs a Launchpad account with a registered GPG key. This can
be the driver maintainer or anyone willing to run the uploads; the GitHub
release `.deb`s remain the channel for Debian.

## Updating

Bump `LIBFPRINT_REF` in `build-deb.sh` (or pass it in the environment) to
move to a new libfprint tag. The driver version is taken from the checked-out
commit, so a new release tag rebuilds with the current driver automatically.
