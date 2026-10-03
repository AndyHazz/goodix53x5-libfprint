# Built by packaging/build-package.sh, which defines goodix_version and
# goodix_changelog_date.
%global debug_package %{nil}
%global fprintd_version 1.94.5
# The private libfprint must not satisfy or create system libfprint dependencies.
%global __provides_exclude_from ^%{_libdir}/libfprint-goodix53x5/.*$
%global __requires_exclude ^libfprint-2\\.so\\.2.*$

Name:           goodix53x5-libfprint
Version:        %{goodix_version}
Release:        1%{?dist}
Summary:        Goodix 53x5 Milan fingerprint driver for libfprint and fprintd
License:        LGPL-2.1-or-later AND GPL-2.0-or-later
URL:            https://github.com/AndyHazz/goodix53x5-libfprint
Source0:        %{name}-%{version}.tar.xz

BuildRequires:  binutils
BuildRequires:  coreutils
BuildRequires:  findutils
BuildRequires:  gcc
BuildRequires:  gcc-c++
BuildRequires:  gettext
BuildRequires:  git-core
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  pam-devel
BuildRequires:  perl-podlators
BuildRequires:  pkgconfig(cairo)
BuildRequires:  pkgconfig(gio-unix-2.0)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gusb)
BuildRequires:  pkgconfig(libdeflate)
BuildRequires:  pkgconfig(libsystemd)
BuildRequires:  pkgconfig(openssl)
BuildRequires:  pkgconfig(polkit-gobject-1)
BuildRequires:  pkgconfig(systemd)
BuildRequires:  python3
BuildRequires:  systemd-rpm-macros
BuildRequires:  util-linux-core

%description
The goodix53x5 libfprint driver for Goodix HTK32 USB fingerprint sensors
27c6:5335, 27c6:5385 and 27c6:5395, with the paired fprintd daemon.

%package -n fprintd-goodix53x5
Summary:        Goodix 53x5 Milan fingerprint driver with fprintd and PAM module
License:        LGPL-2.1-or-later AND GPL-2.0-or-later
Requires:       dbus
Requires:       polkit
Provides:       fprintd = %{fprintd_version}
Provides:       fprintd%{?_isa} = %{fprintd_version}
Provides:       fprintd-pam = %{fprintd_version}
Provides:       fprintd-pam%{?_isa} = %{fprintd_version}
Provides:       fprintd-devel = %{fprintd_version}
Obsoletes:      fprintd < 1.95
Obsoletes:      fprintd-pam < 1.95
Obsoletes:      fprintd-devel < 1.95
# 1.0.0 shipped the private libfprint as a separate package.
Provides:       libfprint-goodix53x5 = %{version}-%{release}
Provides:       libfprint-goodix53x5%{?_isa} = %{version}-%{release}
Obsoletes:      libfprint-goodix53x5 < 1.0.1

%description -n fprintd-goodix53x5
The native Milan fingerprint driver for the Goodix HTK32 USB sensors
27c6:5335, 27c6:5385 and 27c6:5395 (Dell XPS 13 9305 and related laptops),
with adaptive template learning, packaged with a matching fprintd 1.94.5 and
its PAM module.

The driver's libfprint is installed in a private directory used only by this
fprintd; the distribution's libfprint is not replaced. fprintd saves templates
improved by successful matches and keeps the sensor session open between
unlocks and across suspend. This package replaces the distribution's fprintd
and fprintd-pam and supports only the Goodix sensors above; other fingerprint
readers stop working while it is installed.

Enable fingerprint login with "authselect enable-feature with-fingerprint".

%prep
%setup -q
# Both upstream licenses are named COPYING, and license files install by basename.
cp -p sources/libfprint/COPYING COPYING.libfprint
cp -p sources/fprintd/COPYING COPYING.fprintd

%build
%set_build_flags
GOODIX53X5_DEBUG=0 GOODIX_MILAN_STACK_ROOT="$PWD/.build/milan-stack" \
  ./scripts/build-milan-stack-local.sh --package-root "$PWD/.build/root"

%install
cp -a .build/root/. %{buildroot}/
install -d -m 0700 %{buildroot}%{_sharedstatedir}/fprint
%find_lang fprintd

%pre -n fprintd-goodix53x5
for path in /usr/share/goodix53x5-milan/inventory.json /opt/goodix53x5-milan \
    /etc/systemd/system/fprintd.service.d/98-goodix53x5-milan-stack.conf; do
  if [ -e "$path" ]; then
    printf '%s\n' "fprintd-goodix53x5: found a source installation made by ./install.sh:" \
      "  $path" \
      "Remove it with ./uninstall.sh from the checkout that installed it," \
      "then install this package again." >&2
    exit 1
  fi
done

%post -n fprintd-goodix53x5
if [ "$1" -eq 1 ]; then
  printf '%s\n' "fprintd-goodix53x5: enable fingerprint login with:" \
    "  sudo authselect enable-feature with-fingerprint"
  if ls -d /var/lib/fprint/*/goodix53x5 >/dev/null 2>&1; then
    printf '%s\n' "fprintd-goodix53x5: existing goodix53x5 prints were found." \
      "Prints enrolled with the older sigfm driver are not compatible. If" \
      "verification reports invalid data, delete them with fprintd-delete" \
      "and enroll again."
  fi
fi

%preun -n fprintd-goodix53x5
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
  systemctl stop fprintd.service || :
fi

%postun -n fprintd-goodix53x5
if [ "$1" -eq 0 ]; then
  authselect disable-feature with-fingerprint >/dev/null 2>&1 || :
  if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || :
  fi
  udevadm control --reload-rules >/dev/null 2>&1 || :
  printf '%s\n' "fprintd-goodix53x5 was removed. Restore the distribution's fingerprint" \
    "support with: sudo dnf install fprintd fprintd-pam"
fi

# Runs after replaced fprintd packages have been removed.
%posttrans -n fprintd-goodix53x5
sensor=no
for device in /sys/bus/usb/devices/*; do
  [ "$(cat "$device/idVendor" 2>/dev/null)" = 27c6 ] || continue
  case "$(cat "$device/idProduct" 2>/dev/null)" in
    5335|5385|5395) sensor=yes ;;
  esac
done
udevadm control --reload-rules >/dev/null 2>&1 || :
udevadm trigger --subsystem-match=usb --attr-match=idVendor=27c6 --action=add >/dev/null 2>&1 || :
if [ "$sensor" = no ]; then
  printf '%s\n' "fprintd-goodix53x5: no Goodix 27c6:5335, 27c6:5385 or 27c6:5395 sensor" \
    "found; other fingerprint readers are not supported." >&2
fi
if [ -d /run/systemd/system ]; then
  systemctl daemon-reload || :
  if [ "$sensor" = yes ]; then
    # Open the sensor now rather than on the first unlock.
    systemctl restart fprintd.service || :
  else
    systemctl try-restart fprintd.service || :
  fi
fi

%files -n fprintd-goodix53x5 -f fprintd.lang
%license COPYING.libfprint
%license COPYING.fprintd
%{_libdir}/libfprint-goodix53x5/
%config(noreplace) %{_sysconfdir}/fprintd.conf
%{_bindir}/fprintd-*
%{_libexecdir}/fprintd
%{_libdir}/security/pam_fprintd.so
%{_unitdir}/fprintd.service
%{_udevrulesdir}/99-goodix53x5-milan-persist.rules
%{_datadir}/dbus-1/interfaces/net.reactivated.Fprint.*.xml
%{_datadir}/dbus-1/system-services/net.reactivated.Fprint.service
%{_datadir}/dbus-1/system.d/net.reactivated.Fprint.conf
%{_datadir}/polkit-1/actions/net.reactivated.fprint.device.policy
%{_mandir}/man1/fprintd*.1*
%{_mandir}/man8/pam_fprintd.8*
%attr(0700,root,root) %dir %{_sharedstatedir}/fprint

%changelog
* %{goodix_changelog_date} AndyHazz <andy.nmc@gmail.com> - %{version}-%{release}
- Release %{version}. Release notes: https://github.com/AndyHazz/goodix53x5-libfprint/releases
