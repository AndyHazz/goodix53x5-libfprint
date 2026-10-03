/* Read the Windows PSK from a Goodix 53x5 sensor without making
 * persistent writes. This is a migration utility, not driver code. */

#include <errno.h>
#include <fcntl.h>
#include <gio/gio.h>
#include <glib/gstdio.h>
#include <gusb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define GOODIX_VID 0x27c6
#define GOODIX_INTERFACE 1
#define GOODIX_EP_OUT 0x03
#define GOODIX_EP_IN 0x81
#define GOODIX_CHUNK_SIZE 64
#define GOODIX_TIMEOUT_MS 2000
#define GOODIX_MAX_MESSAGE (64 * 1024)
#define GOODIX_READ_SEALED_PSK 0xB001

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

  while (message->len < expected || expected == 0)
    {
      gsize actual_length = 0;
      gsize data_offset = 0;
      gsize append_length;

      if (!bulk_read (device, chunk, &actual_length, GOODIX_TIMEOUT_MS, error))
        return NULL;
      if (actual_length == 0)
        continue;

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
                           "Migration utility command exceeds one USB chunk");
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

static gboolean
read_sealed_psk (GUsbDevice  *device,
                 guint8     **sealed_psk,
                 gsize       *sealed_psk_length,
                 gboolean    *matches_psk_hash,
                 GError     **error)
{
  const guint8 ping_payload[] = { 0x00, 0x00 };
  const guint8 firmware_payload[] = { 0x00, 0x00 };
  const guint8 reset_payload[] = { 0x01, 0x14 };
  guint8 read_payload[] = { 0x01, 0xB0, 0x00, 0x00 };
  g_autoptr(GByteArray) reply = NULL;
  const guint8 *payload;
  gsize payload_length;
  guint32 type;
  guint32 data_length;

  reply = run_command (device, 0x00, 0x00, ping_payload,
                       sizeof (ping_payload), FALSE, error);
  if (!reply)
    return FALSE;

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0A, 0x04, firmware_payload,
                       sizeof (firmware_payload), TRUE, error);
  if (!reply || !parse_reply (reply, 0x0A, 0x04, &payload,
                              &payload_length, error))
    return FALSE;

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0A, 0x01, reset_payload,
                       sizeof (reset_payload), FALSE, error);
  if (!reply)
    return FALSE;
  g_usleep (10 * 1000);

  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0E, 0x02, read_payload,
                       sizeof (read_payload), TRUE, error);
  if (!reply || !parse_reply (reply, 0x0E, 0x02, &payload,
                              &payload_length, error))
    return FALSE;
  if (payload_length < 9 || payload[0] != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Goodix sealed PSK read failed");
      return FALSE;
    }

  type = payload[1] | ((guint32) payload[2] << 8) |
         ((guint32) payload[3] << 16) | ((guint32) payload[4] << 24);
  data_length = payload[5] | ((guint32) payload[6] << 8) |
                ((guint32) payload[7] << 16) | ((guint32) payload[8] << 24);
  if (type != GOODIX_READ_SEALED_PSK || data_length != payload_length - 9 ||
      data_length == 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Malformed Goodix sealed PSK reply");
      return FALSE;
    }

  *sealed_psk = g_memdup2 (payload + 9, data_length);
  *sealed_psk_length = data_length;

  read_payload[0] = 0x03;
  g_clear_pointer (&reply, g_byte_array_unref);
  reply = run_command (device, 0x0E, 0x02, read_payload,
                       sizeof (read_payload), TRUE, error);
  if (!reply || !parse_reply (reply, 0x0E, 0x02, &payload,
                              &payload_length, error))
    return FALSE;
  if (payload_length < 9 || payload[0] != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Goodix PSK hash read failed");
      return FALSE;
    }

  type = payload[1] | ((guint32) payload[2] << 8) |
         ((guint32) payload[3] << 16) | ((guint32) payload[4] << 24);
  data_length = payload[5] | ((guint32) payload[6] << 8) |
                ((guint32) payload[7] << 16) | ((guint32) payload[8] << 24);
  if (type != 0xB003 || data_length != payload_length - 9 || data_length != 32)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "Malformed Goodix PSK hash reply");
      return FALSE;
    }

  if (*sealed_psk_length == 32)
    {
      g_autoptr(GChecksum) checksum = g_checksum_new (G_CHECKSUM_SHA256);
      guint8 digest[32];
      gsize digest_length = sizeof (digest);

      g_checksum_update (checksum, *sealed_psk, *sealed_psk_length);
      g_checksum_get_digest (checksum, digest, &digest_length);
      *matches_psk_hash = memcmp (digest, payload + 9, sizeof (digest)) == 0;
    }
  return TRUE;
}

static gboolean
write_private_file (const gchar  *path,
                    const guint8 *data,
                    gsize         length,
                    GError      **error)
{
  gint fd = g_open (path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0600);
  gsize offset = 0;

  if (fd < 0)
    {
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (errno),
                   "Cannot create %s: %s", path, g_strerror (errno));
      return FALSE;
    }

  while (offset < length)
    {
      ssize_t written = write (fd, data + offset, length - offset);

      if (written < 0 && errno == EINTR)
        continue;
      if (written <= 0)
        {
          gint saved_errno = written < 0 ? errno : EIO;
          close (fd);
          g_unlink (path);
          g_set_error (error, G_FILE_ERROR,
                       g_file_error_from_errno (saved_errno),
                       "Cannot write %s: %s", path,
                       g_strerror (saved_errno));
          return FALSE;
        }
      offset += written;
    }

  if (fsync (fd) != 0)
    {
      gint saved_errno = errno;
      close (fd);
      g_unlink (path);
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
                   "Cannot finish %s: %s", path, g_strerror (saved_errno));
      return FALSE;
    }
  if (close (fd) != 0)
    {
      gint saved_errno = errno;
      g_unlink (path);
      g_set_error (error, G_FILE_ERROR, g_file_error_from_errno (saved_errno),
                   "Cannot close %s: %s", path, g_strerror (saved_errno));
      return FALSE;
    }
  return TRUE;
}

static gboolean
self_test (void)
{
  guint8 data[80];
  guint8 payload[89] = { 0 };
  g_autoptr(GByteArray) message = NULL;
  const guint8 *parsed;
  gsize parsed_length;
  g_autoptr(GError) error = NULL;

  for (guint i = 0; i < sizeof (data); i++)
    data[i] = i;
  payload[1] = 0x01;
  payload[2] = 0xB0;
  payload[5] = sizeof (data);
  memcpy (payload + 9, data, sizeof (data));
  message = build_message (0x0E, 0x02, payload, sizeof (payload));

  return validate_message (message->data, message->len, &error) &&
         parse_reply (message, 0x0E, 0x02, &parsed, &parsed_length, &error) &&
         parsed_length == sizeof (payload) &&
         memcmp (parsed + 9, data, sizeof (data)) == 0;
}

static gboolean
read_device_psk (GUsbDevice  *device,
                 guint8     **psk,
                 gsize       *psk_length,
                 GError     **error)
{
  gboolean opened = FALSE;
  gboolean claimed = FALSE;
  gboolean matches_psk_hash = FALSE;
  gboolean success = FALSE;

  if (!g_usb_device_open (device, error))
    goto out;
  opened = TRUE;
  if (!g_usb_device_claim_interface (
        device, GOODIX_INTERFACE,
        G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, error))
    goto out;
  claimed = TRUE;

  if (!drain_input (device, error) ||
      !read_sealed_psk (device, psk, psk_length, &matches_psk_hash, error))
    goto out;
  if (!matches_psk_hash)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_NOT_SUPPORTED,
                           "B001 is not the active plaintext PSK");
      goto out;
    }

  success = TRUE;

out:
  if (claimed)
    g_usb_device_release_interface (
      device, GOODIX_INTERFACE,
      G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, NULL);
  if (opened)
    g_usb_device_close (device, NULL);
  return success;
}

int
main (int argc, char **argv)
{
  g_autoptr(GUsbContext) context = NULL;
  g_autoptr(GPtrArray) devices = NULL;
  g_autoptr(GError) error = NULL;
  g_autofree guint8 *psk = NULL;
  gsize psk_length = 0;
  gboolean found_goodix = FALSE;
  gboolean found_compatible = FALSE;
  gint status = 1;

  if (argc == 2 && g_str_equal (argv[1], "--self-test"))
    return self_test () ? 0 : 1;
  if (argc != 2)
    {
      g_printerr ("Usage: %s OUTPUT_FILE\n", argv[0]);
      return 2;
    }

  context = g_usb_context_new (&error);
  if (!context)
    goto out;
  g_usb_context_enumerate (context);
  devices = g_usb_context_get_devices (context);
  for (guint i = 0; i < devices->len; i++)
    {
      GUsbDevice *candidate = g_ptr_array_index (devices, i);
      g_autoptr(GError) candidate_error = NULL;

      if (g_usb_device_get_vid (candidate) != GOODIX_VID)
        continue;
      found_goodix = TRUE;
      if (read_device_psk (candidate, &psk, &psk_length, &candidate_error))
        {
          found_compatible = TRUE;
          break;
        }

      g_printerr ("Skipping Goodix %04x:%04x: %s\n",
                  g_usb_device_get_vid (candidate),
                  g_usb_device_get_pid (candidate),
                  candidate_error ? candidate_error->message :
                  "unknown protocol error");
      g_clear_pointer (&psk, g_free);
      psk_length = 0;
    }

  if (!found_compatible)
    {
      g_set_error_literal (&error, G_USB_DEVICE_ERROR,
                           found_goodix ? G_USB_DEVICE_ERROR_NOT_SUPPORTED :
                           G_USB_DEVICE_ERROR_NO_DEVICE,
                           found_goodix ?
                           "No compatible Goodix fingerprint sensor found" :
                           "No Goodix USB device found");
      goto out;
    }
  if (!write_private_file (argv[1], psk, psk_length, &error))
    goto out;

  g_print ("Saved verified %zu-byte Windows PSK to %s\n",
           psk_length, argv[1]);
  g_print ("B001 SHA-256 matches the active B003 PSK hash\n");
  status = 0;

out:
  if (error)
    g_printerr ("error: %s\n", error->message);
  return status;
}
