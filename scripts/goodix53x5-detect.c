/* Identify Goodix devices that may be compatible with the 53x5 Milan driver.
 * The probe makes no persistent device writes and captures no biometric data. */

#include <gio/gio.h>
#include <gusb.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#define GOODIX_VID 0x27c6
#define GOODIX_INTERFACE 1
#define GOODIX_EP_OUT 0x03
#define GOODIX_EP_IN 0x81
#define GOODIX_CHUNK_SIZE 64
#define GOODIX_TIMEOUT_MS 2000
#define GOODIX_MAX_MESSAGE (64 * 1024)
#define MILAN_CHIP_FAMILY_MASK 0xffffff00u
#define MILAN_CHIP_FAMILY_PREFIX 0x00220c00u
#define SYMBOL_CHECK "\xe2\x9c\x93"
#define SYMBOL_CROSS "\xe2\x9c\x97"
#define SYMBOL_WARN  "\xe2\x9a\xa0"

typedef enum
{
  PROBE_COMPATIBLE,
  PROBE_INCOMPATIBLE,
  PROBE_INCONCLUSIVE,
} ProbeResult;

typedef struct
{
  guint16     vid;
  guint16     pid;
  guint32     chip_id;
  gchar      *firmware;
  ProbeResult result;
  gchar      *reason;
} ProbeReport;

static gboolean use_color;

static const gchar *
color (const gchar *ansi)
{
  return use_color ? ansi : "";
}

static void
print_result (const gchar *ansi,
              const gchar *symbol,
              const gchar *text)
{
  g_print ("\n%s", color (ansi));
  fputs (symbol, stdout);
  g_print (" %s%s\n", text, color ("\033[0m"));
}

static guint8
checksum_for (const guint8 *data,
              gsize         length)
{
  guint sum = 0;

  for (gsize i = 0; i < length; i++)
    sum += data[i];
  return (0xAA - sum) & 0xFF;
}

static GByteArray *
build_message (guint8        category,
               guint8        command,
               const guint8 *payload,
               gsize         payload_length)
{
  GByteArray *message = g_byte_array_sized_new (payload_length + 4);
  guint8 header[3] = {
    (category << 4) | (command << 1),
    (payload_length + 1) & 0xFF,
    ((payload_length + 1) >> 8) & 0xFF,
  };
  guint8 checksum;

  g_byte_array_append (message, header, sizeof (header));
  g_byte_array_append (message, payload, payload_length);
  checksum = checksum_for (message->data, message->len);
  g_byte_array_append (message, &checksum, 1);
  return message;
}

static gboolean
validate_message (const guint8 *message,
                  gsize         length,
                  GError      **error)
{
  gsize expected;
  guint8 received_checksum;

  if (length < 4)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Goodix message is shorter than its header");
      return FALSE;
    }

  expected = 3 + message[1] + ((gsize) message[2] << 8);
  if (expected != length)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Goodix message length mismatch: expected %zu, got %zu",
                   expected, length);
      return FALSE;
    }

  received_checksum = message[length - 1];
  if (received_checksum != 0x88 &&
      received_checksum != checksum_for (message, length - 1))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Goodix message checksum mismatch");
      return FALSE;
    }

  return TRUE;
}

static gboolean
bulk_read (GUsbDevice *device,
           guint8     *chunk,
           gsize      *actual_length,
           guint       timeout,
           GError    **error)
{
  return g_usb_device_bulk_transfer (device, GOODIX_EP_IN, chunk,
                                     GOODIX_CHUNK_SIZE, actual_length,
                                     timeout, NULL, error);
}

static gboolean
receive_made_progress (gsize     appended,
                       guint    *no_progress_count,
                       GError  **error)
{
  if (appended != 0)
    {
      *no_progress_count = 0;
      return TRUE;
    }
  if (++*no_progress_count <= 8)
    return TRUE;

  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT,
                       "Goodix reply made no progress");
  return FALSE;
}

static gboolean
drain_input (GUsbDevice *device,
             GError    **error)
{
  guint8 chunk[GOODIX_CHUNK_SIZE];

  for (guint i = 0; i < 64; i++)
    {
      gsize actual_length = 0;
      g_autoptr(GError) read_error = NULL;

      if (bulk_read (device, chunk, &actual_length, 50, &read_error))
        continue;
      if (g_error_matches (read_error, G_USB_DEVICE_ERROR,
                           G_USB_DEVICE_ERROR_TIMED_OUT))
        return TRUE;

      g_propagate_error (error, g_steal_pointer (&read_error));
      return FALSE;
    }

  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_BUSY,
                       "Goodix input did not become idle");
  return FALSE;
}

static GByteArray *
receive_message (GUsbDevice *device,
                 GError    **error)
{
  g_autoptr(GByteArray) message = g_byte_array_new ();
  guint8 chunk[GOODIX_CHUNK_SIZE];
  guint8 command_byte = 0;
  gsize expected = 0;
  guint no_progress_count = 0;

  while (message->len < expected || expected == 0)
    {
      gsize actual_length = 0;
      gsize data_offset = 0;
      gsize append_length;

      if (!bulk_read (device, chunk, &actual_length, GOODIX_TIMEOUT_MS, error))
        return NULL;
      if (actual_length == 0)
        {
          if (!receive_made_progress (0, &no_progress_count, error))
            return NULL;
          continue;
        }

      if (message->len == 0)
        {
          if (actual_length < 3)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                   "Short first Goodix USB chunk");
              return NULL;
            }
          command_byte = chunk[0];
          expected = 3 + chunk[1] + ((gsize) chunk[2] << 8);
          if (expected < 4 || expected > GOODIX_MAX_MESSAGE)
            {
              g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Invalid Goodix message size: %zu", expected);
              return NULL;
            }
        }
      else
        {
          if ((chunk[0] & 1) == 0 || (chunk[0] & 0xFE) != command_byte)
            {
              g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                                   "Invalid Goodix continuation chunk");
              return NULL;
            }
          data_offset = 1;
        }

      append_length = MIN (actual_length - data_offset,
                           expected - message->len);
      if (!receive_made_progress (append_length, &no_progress_count, error))
        return NULL;
      if (append_length == 0)
        continue;
      g_byte_array_append (message, chunk + data_offset, append_length);
    }

  if (!validate_message (message->data, message->len, error))
    return NULL;
  return g_steal_pointer (&message);
}

static GByteArray *
run_command (GUsbDevice   *device,
             guint8        category,
             guint8        command,
             const guint8 *payload,
             gsize         payload_length,
             gboolean      expect_reply,
             GError      **error)
{
  g_autoptr(GByteArray) request = NULL;
  g_autoptr(GByteArray) ack = NULL;
  guint8 transfer[GOODIX_CHUNK_SIZE] = { 0 };
  guint8 command_byte;
  gsize actual_length = 0;

  request = build_message (category, command, payload, payload_length);
  if (request->len > sizeof (transfer))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                           "Probe command exceeds one USB chunk");
      return NULL;
    }

  memcpy (transfer, request->data, request->len);
  if (!g_usb_device_bulk_transfer (device, GOODIX_EP_OUT, transfer,
                                   sizeof (transfer), &actual_length,
                                   GOODIX_TIMEOUT_MS, NULL, error))
    return NULL;
  if (actual_length != sizeof (transfer))
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "Short Goodix USB write: %zu", actual_length);
      return NULL;
    }

  command_byte = (category << 4) | (command << 1);
  ack = receive_message (device, error);
  if (!ack)
    return NULL;
  if ((ack->data[0] >> 4) != 0x0B ||
      ((ack->data[0] & 0x0F) >> 1) != 0 ||
      ack->len < 6 || ack->data[3] != command_byte ||
      (ack->data[4] & 1) == 0)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Invalid ACK for Goodix command 0x%02x", command_byte);
      return NULL;
    }

  if (!expect_reply)
    return g_byte_array_new ();
  return receive_message (device, error);
}

static gboolean
parse_reply (GByteArray   *message,
             guint8        category,
             guint8        command,
             const guint8 **payload,
             gsize         *payload_length,
             GError       **error)
{
  if ((message->data[0] >> 4) != category ||
      ((message->data[0] & 0x0F) >> 1) != command)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Unexpected Goodix reply 0x%02x", message->data[0]);
      return FALSE;
    }

  *payload = message->data + 3;
  *payload_length = message->len - 4;
  return TRUE;
}

static guint8
otp_hash_step (guint8 value)
{
  for (guint bit = 0; bit < 8; bit++)
    value = (value & 0x80) != 0 ? (value << 1) ^ 0x07 : value << 1;
  return value;
}

static gboolean
verify_otp (const guint8 *otp,
            gsize         otp_length)
{
  guint8 checksum = 0;

  if (otp_length < 27)
    return FALSE;
  for (gsize i = 0; i < otp_length; i++)
    if (i != 25)
      checksum = otp_hash_step (checksum ^ otp[i]);
  return otp[25] == ((~checksum) & 0xFF);
}

static guint32
decode_chip_id (const guint8 *data)
{
  return (guint32) data[0] * 0x100 +
         (guint32) data[1] +
         (guint32) data[2] * 0x1000000 +
         (guint32) data[3] * 0x10000;
}

static gchar *
sanitize_firmware (const guint8 *data,
                   gsize         length)
{
  GString *result = g_string_sized_new (MIN (length, 80));

  for (gsize i = 0; i < length && i < 80 && data[i] != 0; i++)
    g_string_append_c (result, g_ascii_isprint (data[i]) ? data[i] : '?');
  return g_string_free (result, FALSE);
}

static gboolean
has_expected_usb_layout (GUsbDevice *device,
                         GError    **error)
{
  g_autoptr(GPtrArray) interfaces = NULL;

  interfaces = g_usb_device_get_interfaces (device, error);
  if (!interfaces)
    return FALSE;

  for (guint i = 0; i < interfaces->len; i++)
    {
      GUsbInterface *iface = g_ptr_array_index (interfaces, i);
      g_autoptr(GPtrArray) endpoints = NULL;
      gboolean has_in = FALSE;
      gboolean has_out = FALSE;

      if (g_usb_interface_get_number (iface) != GOODIX_INTERFACE ||
          g_usb_interface_get_alternate (iface) != 0)
        continue;
      endpoints = g_usb_interface_get_endpoints (iface);
      if (!endpoints)
        continue;
      for (guint j = 0; j < endpoints->len; j++)
        {
          GUsbEndpoint *endpoint = g_ptr_array_index (endpoints, j);
          guint8 address = g_usb_endpoint_get_address (endpoint);

          has_in |= address == GOODIX_EP_IN;
          has_out |= address == GOODIX_EP_OUT;
        }
      if (has_in && has_out)
        return TRUE;
    }

  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                       "USB interface 1 does not expose endpoints 0x03 and 0x81");
  return FALSE;
}

static gboolean
parse_production_hash (const guint8 *payload,
                       gsize         payload_length)
{
  guint32 type;
  guint32 data_length;

  if (payload_length < 9 || payload[0] != 0)
    return FALSE;
  type = payload[1] | ((guint32) payload[2] << 8) |
         ((guint32) payload[3] << 16) | ((guint32) payload[4] << 24);
  data_length = payload[5] | ((guint32) payload[6] << 8) |
                ((guint32) payload[7] << 16) | ((guint32) payload[8] << 24);
  return type == 0xB003 && data_length == 32 &&
         data_length == payload_length - 9;
}

static void
finish_report (ProbeReport *report,
               const GError *error,
               const GError *cleanup_error)
{
  if (cleanup_error && report->result == PROBE_COMPATIBLE)
    report->result = PROBE_INCONCLUSIVE;
  if (error && cleanup_error)
    report->reason = g_strdup_printf ("%s; cleanup failed: %s",
                                      error->message, cleanup_error->message);
  else if (error)
    report->reason = g_strdup (error->message);
  else if (cleanup_error)
    report->reason = g_strdup_printf ("Device cleanup failed: %s",
                                      cleanup_error->message);
}

static ProbeResult
probe_device (GUsbDevice  *device,
              ProbeReport *report)
{
  const guint8 ping_payload[] = { 0x00, 0x00 };
  const guint8 firmware_payload[] = { 0x00, 0x00 };
  const guint8 reset_payload[] = { 0x01, 0x14 };
  const guint8 chip_payload[] = { 0x00, 0x00, 0x00, 0x04, 0x00 };
  const guint8 otp_payload[] = { 0x00, 0x00 };
  const guint8 psk_hash_payload[] = { 0x03, 0xB0, 0x00, 0x00 };
  const guint8 sleep_payload[] = { 0x01, 0x00 };
  g_autoptr(GByteArray) reply = NULL;
  g_autoptr(GError) error = NULL;
  g_autoptr(GError) cleanup_error = NULL;
  const guint8 *payload;
  gsize payload_length;
  gboolean opened = FALSE;
  gboolean claimed = FALSE;
  gboolean protocol_started = FALSE;

  report->result = PROBE_INCONCLUSIVE;
  if (!has_expected_usb_layout (device, &error))
    {
      if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED))
        report->result = PROBE_INCOMPATIBLE;
      goto out;
    }
  if (!g_usb_device_open (device, &error))
    goto out;
  opened = TRUE;
  if (!g_usb_device_claim_interface (
        device, GOODIX_INTERFACE,
        G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, &error))
    goto out;
  claimed = TRUE;
  if (!drain_input (device, &error))
    goto out;

  reply = run_command (device, 0x00, 0x00, ping_payload,
                       sizeof (ping_payload), FALSE, &error);
  if (!reply)
    goto out;
  protocol_started = TRUE;

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0A, 0x04, firmware_payload,
                       sizeof (firmware_payload), TRUE, &error);
  if (!reply || !parse_reply (reply, 0x0A, 0x04, &payload,
                              &payload_length, &error))
    goto out;
  report->firmware = sanitize_firmware (payload, payload_length);

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0A, 0x01, reset_payload,
                       sizeof (reset_payload), FALSE, &error);
  if (!reply)
    goto out;
  g_usleep (10 * 1000);

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x08, 0x01, chip_payload,
                       sizeof (chip_payload), TRUE, &error);
  if (!reply || !parse_reply (reply, 0x08, 0x01, &payload,
                              &payload_length, &error))
    goto out;
  if (payload_length != 4)
    {
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                   "Unexpected chip ID length: %zu", payload_length);
      goto out;
    }
  report->chip_id = decode_chip_id (payload);
  if ((report->chip_id & MILAN_CHIP_FAMILY_MASK) !=
      MILAN_CHIP_FAMILY_PREFIX)
    {
      report->result = PROBE_INCOMPATIBLE;
      g_set_error (&error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                   "chip 0x%08x is not in the supported 0x00220cxx family",
                   report->chip_id);
      goto out;
    }

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0A, 0x03, otp_payload,
                       sizeof (otp_payload), TRUE, &error);
  if (!reply || !parse_reply (reply, 0x0A, 0x03, &payload,
                              &payload_length, &error))
    goto out;
  if (!verify_otp (payload, payload_length))
    {
      g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "OTP checksum validation failed");
      goto out;
    }

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0E, 0x02, psk_hash_payload,
                       sizeof (psk_hash_payload), TRUE, &error);
  if (!reply || !parse_reply (reply, 0x0E, 0x02, &payload,
                              &payload_length, &error))
    goto out;
  if (!parse_production_hash (payload, payload_length))
    {
      g_set_error_literal (&error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "PSK hash production record has an unexpected format");
      goto out;
    }

  report->result = PROBE_COMPATIBLE;

out:
  if (protocol_started)
    {
      g_autoptr(GByteArray) sleep_reply = NULL;

      sleep_reply = run_command (device, 0x06, 0x00, sleep_payload,
                                 sizeof (sleep_payload), FALSE, &cleanup_error);
    }
  if (claimed)
    {
      g_autoptr(GError) release_error = NULL;

      if (!g_usb_device_release_interface (
            device, GOODIX_INTERFACE,
            G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, &release_error) &&
          !cleanup_error)
        cleanup_error = g_steal_pointer (&release_error);
    }
  if (opened)
    {
      g_autoptr(GError) close_error = NULL;

      if (!g_usb_device_close (device, &close_error) && !cleanup_error)
        cleanup_error = g_steal_pointer (&close_error);
    }
  finish_report (report, error, cleanup_error);
  return report->result;
}

static gboolean
is_registered_pid (guint16 pid)
{
  return pid == 0x5335 || pid == 0x5385 || pid == 0x5395;
}

static gchar *
read_system_name (void)
{
  g_autofree gchar *vendor = NULL;
  g_autofree gchar *product = NULL;

  if (!g_file_get_contents ("/sys/class/dmi/id/sys_vendor", &vendor, NULL,
                            NULL) ||
      !g_file_get_contents ("/sys/class/dmi/id/product_name", &product, NULL,
                            NULL))
    return NULL;
  g_strstrip (vendor);
  g_strstrip (product);
  return g_strdup_printf ("%s %s", vendor, product);
}

static void
print_report (const ProbeReport *report,
              const gchar       *system_name,
              const gchar       *kernel_release)
{
  g_print ("%sGoodix %04x:%04x%s\n", color ("\033[1;36m"), report->vid,
           report->pid, color ("\033[0m"));
  if (report->firmware && report->firmware[0] != '\0')
    g_print ("Firmware %s\n", report->firmware);
  if (report->chip_id != 0)
    {
      g_print ("Chip 0x%08x", report->chip_id);
      /* Reference-driver profiles and algorithm sensor types are distinct enums. */
      switch (report->chip_id & MILAN_CHIP_FAMILY_MASK)
        {
        case 0x00220200u:
          g_print (" | Milan profile 0 | sensor type 0");
          break;
        case 0x00220700u:
          g_print (" | Milan profile 1 | sensor type 6");
          break;
        case 0x00220800u:
          g_print (" | Milan profile 2 | sensor type 7");
          break;
        case MILAN_CHIP_FAMILY_PREFIX:
          g_print (" | Milan profile 9 | sensor type 12");
          break;
        default:
          break;
        }
      g_print ("\n");
    }
  if (system_name)
    g_print ("System %s | Linux %s\n", system_name, kernel_release);

  switch (report->result)
    {
    case PROBE_COMPATIBLE:
      if (is_registered_pid (report->pid))
        {
          print_result ("\033[1;32m", SYMBOL_CHECK,
                        "MATCH - USB ID already registered");
          g_print ("Hardware validation reports are welcome.\n");
        }
      else
        {
          print_result ("\033[1;32m", SYMBOL_CHECK,
                        "COMPATIBLE CANDIDATE");
          g_print ("Open a compatibility issue and paste this output.\n");
          g_print ("Developers may instead submit a PR adding USB %04x:%04x.\n",
                   report->vid, report->pid);
        }
      break;
    case PROBE_INCOMPATIBLE:
      print_result ("\033[1;31m", SYMBOL_CROSS, "NOT COMPATIBLE");
      if (report->reason)
        g_print ("%s\n", report->reason);
      break;
    case PROBE_INCONCLUSIVE:
      print_result ("\033[1;33m", SYMBOL_WARN, "INCONCLUSIVE");
      if (report->reason)
        g_print ("%s\n", report->reason);
      if (geteuid () != 0)
        g_print ("Try again with sudo after stopping fprintd.\n");
      break;
    }
}

static gboolean
self_test (void)
{
  const guint8 payload[] = { 0x00, 0x00 };
  const guint8 chip_bytes[] = { 0x0c, 0xa1, 0x00, 0x22 };
  guint8 production_payload[41] = { 0 };
  guint8 otp[27] = { 0 };
  guint8 otp_checksum = 0;
  guint no_progress_count = 0;
  ProbeReport cleanup_report = { .result = PROBE_COMPATIBLE };
  g_autoptr(GByteArray) message = build_message (0x0A, 0x04, payload,
                                                 sizeof (payload));
  g_autoptr(GError) error = NULL;
  g_autoptr(GError) cleanup_error = NULL;

  production_payload[1] = 0x03;
  production_payload[2] = 0xB0;
  production_payload[5] = 32;
  for (gsize i = 0; i < sizeof (otp); i++)
    if (i != 25)
      otp_checksum = otp_hash_step (otp_checksum ^ otp[i]);
  otp[25] = (~otp_checksum) & 0xFF;
  if (!validate_message (message->data, message->len, &error) ||
      decode_chip_id (chip_bytes) != 0x00220ca1 ||
      otp_hash_step (0x01) != 0x07 ||
      !verify_otp (otp, sizeof (otp)) ||
      !parse_production_hash (production_payload,
                              sizeof (production_payload)) ||
      parse_production_hash (production_payload,
                             sizeof (production_payload) - 1))
    return FALSE;

  for (guint i = 0; i < 8; i++)
    if (!receive_made_progress (0, &no_progress_count, &error))
      return FALSE;
  if (receive_made_progress (0, &no_progress_count, &error) ||
      !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT))
    return FALSE;
  g_clear_error (&error);

  cleanup_error = g_error_new_literal (G_IO_ERROR, G_IO_ERROR_FAILED,
                                       "release failed");
  finish_report (&cleanup_report, NULL, cleanup_error);
  if (cleanup_report.result != PROBE_INCONCLUSIVE || !cleanup_report.reason)
    return FALSE;
  g_clear_pointer (&cleanup_report.reason, g_free);

  message->data[message->len - 1] ^= 0x01;
  g_clear_error (&error);
  return !validate_message (message->data, message->len, &error);
}

int
main (int argc, char **argv)
{
  g_autoptr(GUsbContext) context = NULL;
  g_autoptr(GPtrArray) devices = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree gchar *system_name = NULL;
  struct utsname uts = { 0 };
  gboolean found_goodix = FALSE;
  gboolean found_compatible = FALSE;
  gboolean found_definite_result = FALSE;

  if (argc == 2 && g_str_equal (argv[1], "--self-test"))
    return self_test () ? 0 : 1;
  if (argc != 1)
    {
      g_printerr ("Usage: %s\n", argv[0]);
      return 2;
    }

  use_color = isatty (STDOUT_FILENO) && g_getenv ("NO_COLOR") == NULL &&
              !g_str_equal (g_getenv ("TERM") ? g_getenv ("TERM") : "",
                            "dumb");
  system_name = read_system_name ();
  uname (&uts);
  context = g_usb_context_new (&error);
  if (!context)
    goto fail;
  g_usb_context_enumerate (context);
  devices = g_usb_context_get_devices (context);
  for (guint i = 0; i < devices->len; i++)
    {
      GUsbDevice *candidate = g_ptr_array_index (devices, i);
      ProbeReport report = { 0 };

      if (g_usb_device_get_vid (candidate) != GOODIX_VID)
        continue;
      found_goodix = TRUE;
      report.vid = g_usb_device_get_vid (candidate);
      report.pid = g_usb_device_get_pid (candidate);
      probe_device (candidate, &report);
      print_report (&report, system_name, uts.release);
      found_compatible |= report.result == PROBE_COMPATIBLE;
      found_definite_result |= report.result != PROBE_INCONCLUSIVE;
      g_clear_pointer (&report.firmware, g_free);
      g_clear_pointer (&report.reason, g_free);
      g_print ("\n");
    }

  if (!found_goodix)
    {
      fputs (SYMBOL_WARN " ", stderr);
      g_printerr ("INCONCLUSIVE: no Goodix USB device found\n");
      return 2;
    }
  if (found_compatible)
    return 0;
  return found_definite_result ? 1 : 2;

fail:
  fputs (SYMBOL_WARN " ", stderr);
  g_printerr ("INCONCLUSIVE: %s\n", error ? error->message : "USB error");
  return 2;
}
