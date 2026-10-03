# fprintd Milan Overlays

`1.94.5-milan-update-save.patch` targets fprintd `v1.94.5` at exact commit
`b54a007ccf58ac0ae074c7151b223f35cbd17306`. It consumes the paired
libfprint terminal update boolean and synchronously saves the already-mutated
matched print through stock `store.print_data_save()`.

Verify saves the object held in `priv->verify_data`; identify saves the exact
match returned by libfprint. Saving occurs once after the match report and
before operation-owned state is cleared. A save failure is logged and discarded
without changing authentication. No storage API, file backend, transaction,
locking, retry, or persistence test subsystem is added.

Verify a pristine pinned checkout:

```sh
./patches/fprintd/verify-update-save-patch.sh /path/to/fprintd-v1.94.5
```

Regenerate deterministically from a modified checkout at the pinned commit:

```sh
./patches/fprintd/generate-update-save-patch.sh /path/to/modified-fprintd
```

The SHA-256 sidecar is authoritative and checked before apply validation.

## Retained hardware session

Apply `1.94.5-serviced-session.patch` **after** the update-save overlay. It
pairs with the libfprint idle suspend/resume patch and the Goodix driver's
background maintenance; the stack scripts build and install them together.

Upstream fprintd opens the sensor on `Claim` and closes it on `Release` or
when the client disappears, so every unlock repeats the driver's cold
initialization. With this overlay enumeration starts an unclaimed open and the
device then stays open, the way the native Windows service keeps its hardware
host resident:

- After exporting a device, the manager makes one asynchronous open attempt
  without a client claim. Success logs `Device N ready before first claim`;
  failure logs an error and leaves the next authorized `Claim` to retry. An
  open is not started while device power handling is pending.
- `Claim` on an already open device completes immediately. A claim arriving
  during eager initialization joins that open and receives its result, without
  starting a second open. Authorization and claim exclusivity still apply.
- `Release` and client disappearance still cancel a running action and wait
  for it (and unset a completed verify/identify/enroll that was never
  stopped), but only end the user's authority; the hardware stays open and
  the driver keeps servicing finger-detection events between claims.
- A removed device is closed on `FpDevice::removed`, since libfprint withholds
  `FpContext::device-removed` until an open device has been closed; the
  manager's existing removal handling then unexports it. Removal while a
  suspend or resume is still in flight is finished from that power task's
  completion, because libfprint rejects close until the task has settled.
- The device's `busy` property is also true while opening or open, so
  the manager never arms its idle exit while a sensor is retained. On
  `SIGTERM` or bus-name loss the manager ends any claim and closes each open
  device for real before storage is deinitialized, waiting for any pending open
  first. The initial idle timeout also respects devices opened at enumeration.
- The manager's existing `PrepareForSleep` handling drives suspend and resume
  as before; the libfprint patch makes the idle-open device reach the driver.
  While the device is asleep or still resuming, a cold `Claim` open and one
  `VerifyStart`/`EnrollStart` are held and dispatched when resume completes,
  instead of failing with a busy device. `VerifyStop`, `EnrollStop`,
  `Release` and client disappearance fail a held start.

The installed Milan udev rule starts `fprintd.service` when a supported sensor
appears; D-Bus activation remains available. Installation already restarts the
daemon, so eager initialization also runs without a reboot. No `--no-timeout`
flag is needed. The sensor remains initialized from daemon startup, with the
driver's event-driven idle servicing and its associated sensor power draw;
that draw has not been measured. Initialization overlaps boot rather than
blocking the greeter, so a claim arriving early still waits for the open.

Nothing else in the daemon changes: authorization, claim ownership checks,
retries, status signals, storage and the update-save overlay behave as
upstream. A positive match is reported to the client as soon as the driver
has validated it; the driver finishes the sensor's deactivation on its own,
so `VerifyStop` and `Release` return promptly.

A hardware fault while idle is handled inside the driver: it stops background
maintenance and the next action reconstructs the sensor session, so no daemon
recovery path is needed. Resume after system sleep reclaims the USB interface
and establishes a fresh GTLS session before the held start runs, retaining the
host reference, calibration and FDT state. Existing hardware faults or a failed
warm resume use one cold reconstruction instead. The same driver path handles
sleep and hibernate; the first FDT arm repairs lost configuration when the
sensor reports status 3. Debug builds log `Hardware resume ready (warm)` or
`Hardware resume ready (cold)` with the elapsed time, without requiring a
capture campaign.

Verify composition and reverse application, or regenerate only this layer:

```sh
./patches/fprintd/verify-serviced-session-patch.sh /path/to/pristine-fprintd
./patches/fprintd/generate-serviced-session-patch.sh /path/to/modified-fprintd
```

The generator diffs `src/device.c`, `src/manager.c`, `src/main.c` and
`src/fprintd.h` against the update-save layer using a temporary index; it
neither commits the source checkout nor alters its index. The stack builder
checks both patch digests and includes both in its overlay identity.
