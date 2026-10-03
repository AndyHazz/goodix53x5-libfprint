# Windows Dual-Boot PSK Migration

Windows and this Linux driver use a GTLS pre-shared key to protect traffic with
the fingerprint sensor. The key is independent of the fingerprint templates
stored by each operating system, so migration does not require re-enrollment.

This is an optional, one-time migration. Without
`/var/lib/fprint/goodix53x5.psk`, the driver retains its normal behavior and
automatically provisions the all-zero Linux PSK when necessary. When that file
exists, the driver uses the imported key and refuses to overwrite a sensor that
does not match it.

> [!WARNING]
> The PSK grants access to encrypted sensor traffic. Keep it private, never
> commit it, and delete transfer copies after installation.

## How It Works

The fingerprint reader has persistent memory shared by both operating systems.
When Windows Hello starts after Linux has used the all-zero key, the official
Goodix driver automatically restores or creates its own key in the reader.

Linux then reads that key directly from the reader over USB. It does not read
the Windows partition and runs no code in Windows. The extractor also reads the
reader's active-key hash and saves the key only when they match. Once installed,
the Linux driver uses the same key and skips PSK provisioning. If the key ever
does not match, Linux fails without replacing it.

## Requirements

- A Goodix USB fingerprint sensor using the same PSK production records.
- The updated driver installed before beginning migration.
- `cc`, `pkg-config`, and GUsb development files on Linux. These are already
  driver build dependencies.
- Administrator access on Linux and password or PIN login while fingerprint
  authentication is temporarily disabled.

Hardware validation currently covers `27c6:5335`. Its `B001` production value
is the raw 32-byte PSK. The extractor does not restrict Goodix product IDs: it
probes attached Goodix devices and writes a file only when `SHA256(B001)` equals
the active `B003` hash. Devices using another protocol or sealing format fail
without producing a key.

## 1. Install And Disable Linux Fingerprint Access

Install the release packages or a release build with `./install.sh`, or retain
debug capture support with a source installation:

```sh
./install.sh --debug
```

Before booting Windows, mask `fprintd`:

```sh
sudo systemctl mask --now fprintd.service
```

Masking persists across reboots and prevents desktop, PAM, or D-Bus activation
from opening the sensor when Linux next starts. Otherwise the normal driver
could replace the freshly established Windows key before the standalone dumper
reads it. Existing Linux enrollments are not deleted.

## 2. Establish The Windows Key

Boot Windows and perform a Windows Hello fingerprint operation. This gives the
Goodix driver an opportunity to detect the previous Linux key and restore or
replace it. Use a PIN or password first if fingerprint sign-in is temporarily
unavailable, then reboot into Linux.

## 3. Extract And Install The Key

Keep `fprintd` masked. From the repository checkout, run:

```sh
sudo ./scripts/extract-windows-psk.sh ./goodix53x5-windows.psk
sudo ./scripts/install-windows-psk.sh ./goodix53x5-windows.psk
```

The dumper verifies that `fprintd` is masked and inactive, compiles a standalone
GUsb reader, reads `B001` and `B003`, and writes the key only when their hashes
match. It makes no persistent sensor writes and does not start GTLS.

The installer stores the key as 64 hexadecimal characters at
`/var/lib/fprint/goodix53x5.psk`, owned by root with mode `0600`. If a key was
installed previously, replacement requires `--replace` and preserves the old
file as `/var/lib/fprint/goodix53x5.psk.previous`.

## 4. Restore And Verify

```sh
sudo systemctl unmask fprintd.service
sudo systemctl restart fprintd.service
fprintd-verify
```

After verification succeeds, delete the extracted transfer copy:

```sh
rm ./goodix53x5-windows.psk
```

For final confirmation, boot Windows and unlock with Windows Hello, then boot
Linux and run `fprintd-verify` again. If both succeed, neither transition
replaced the shared key. A debug build (`./install.sh --debug`) also logs
`PSK hash matches, no need to write` to the `fprintd.service` journal when it
opens the sensor.

If an imported key does not match, the driver fails without changing the
sensor. Re-extract the current Windows key. Removing
`/var/lib/fprint/goodix53x5.psk` intentionally returns to Linux-only mode, where
the normal driver may replace the Windows key with its all-zero key.
