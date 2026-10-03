# Libfprint Update Result Overlay

`libfprint-update-result.patch` is an additive Patch A overlay for libfprint
`v1.94.10` at exact commit
`0c97a47d8ef405cd577b87058c1e89cae9d242e7`.

The patch is the narrow private contract shared by the repository's Milan
driver and pinned fprintd build. The driver mutates a validated matched raw
print in place, reports matches through the stock APIs, and supplies one update
boolean only at terminal verify or identify completion. Existing finish APIs
remain wrappers that ignore the boolean. One focused test covers positive,
no-match, and terminal-error propagation.

`scripts/build-local.sh` verifies and applies this patch immediately after the
pinned checkout and before copying the driver overlay or configuring Meson.
The build fails deterministically on a wrong revision, tracked source changes,
or patch context drift. Untracked build/overlay files are ignored because the
local checkout intentionally retains them between builds. To perform the same
check manually:

```sh
./patches/libfprint/verify-update-result-patch.sh /path/to/pristine/libfprint
```

Regenerate it deterministically from a modified worktree at the pinned commit:

```sh
./patches/libfprint/generate-update-result-patch.sh /path/to/modified/libfprint
```

The generator writes a base-revision header into the patch. The verifier
enforces that revision before running `git apply --check`; `git apply` alone
does not enforce patch metadata.

## Idle suspend and resume

`libfprint-idle-suspend-notify.patch` lets the Goodix driver keep servicing its
hardware while no action runs. The open device holds the sensor between
fprintd claims, so the core must tell the driver about system sleep even when
the device is idle. Upstream completes an idle suspend or resume without
touching the driver.

The patch changes only that dispatch in `fpi_device_suspend()` and
`fpi_device_resume()`:

- an open device with no current action calls the driver's existing `suspend`
  and `resume` vfuncs instead of completing immediately;
- a suspend that overlaps a short action (open, close, delete, list, clear)
  is dispatched again once that action completes, so a device opened during
  the transition is still quiesced;
- `fp_device_close()` is rejected while a suspend or resume task is pending
  (its completion would close the USB handle underneath the power owner) and
  admitted for a completed suspend, so a device removed during sleep can be
  closed without resuming hardware and the context can finish its removal.

The driver completes both asynchronously with `fpi_device_suspend_complete()`
and `fpi_device_resume_complete()`. Suspend joins all background hardware work
and sleeps the sensor; resume reclaims USB and re-keys GTLS while retaining host
calibration/reference state, with one cold reconstruction on failure, before it
completes. Actions that arrive while the driver is quiescing fail with `FP_DEVICE_ERROR_BUSY`
from the driver; the core rejects them itself once suspend has completed.

Four assertions in `tests/test-fpi-device.c` are updated for the new idle
dispatch. No new core API, signal or feature flag is added; the paired fprintd
overlay only relies on the driver-side behaviour above.

Both local build routes verify and apply the patch, and include it in overlay
and production source identities. Check it against a pristine checkout with:

```sh
./patches/libfprint/verify-idle-suspend-notify-patch.sh /path/to/pristine/libfprint
```

Regenerate it from a pristine checkout carrying only these edits:

```sh
./patches/libfprint/generate-idle-suspend-notify-patch.sh /path/to/modified/libfprint
```
