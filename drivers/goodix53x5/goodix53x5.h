/*
 * Goodix 53x5 driver for libfprint
 * Copyright (C) 2024 goodix-fp-linux-dev contributors
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"
#include "fpi-usb-transfer.h"
#include <openssl/evp.h>
#include <openssl/rand.h>

G_DECLARE_FINAL_TYPE (FpiDeviceGoodix53x5, fpi_device_goodix53x5, FPI,
                      DEVICE_GOODIX53X5, FpDevice)

/* USB endpoints — interface 1, CDC Data class */
#define GOODIX_EP_OUT (0x03 | FPI_USB_ENDPOINT_OUT)
#define GOODIX_EP_IN  (0x01 | FPI_USB_ENDPOINT_IN)
#define GOODIX_USB_INTERFACE 1

/* USB chunk size */
#define GOODIX_USB_CHUNK_SIZE 64

/* Sensor dimensions */
#define GOODIX_SENSOR_WIDTH  108
#define GOODIX_SENSOR_HEIGHT 88
#define GOODIX_SENSOR_PIXELS (GOODIX_SENSOR_WIDTH * GOODIX_SENSOR_HEIGHT)

/* 12-bit packed: 6 bytes per 4 pixels */
#define GOODIX_RAW_FRAME_SIZE (GOODIX_SENSOR_PIXELS * 6 / 4)

/* FDT base length */
#define GOODIX_FDT_BASE_LEN 24

/* Enroll stages */
#define GOODIX_ENROLL_SAMPLES 8

/* SIGFM (SIFT-based) matching parameters */
#define GOODIX_SIGFM_THRESHOLD    10   /* minimum sigfm score for match */

/* Timeouts in ms */
#define GOODIX_CMD_TIMEOUT    1000
#define GOODIX_ACK_TIMEOUT    2000
#define GOODIX_DATA_TIMEOUT   5000
#define GOODIX_EMPTY_TIMEOUT  200

/* HV value for image capture */
#define GOODIX_HV_VALUE 6

/* Max reassembly buffer (encrypted image can be ~15KB) */
#define GOODIX_RX_BUF_SIZE (16 * 1024)

/* Protocol: message format is [cmd_byte(1)][size(2 LE)][payload(N)][checksum(1)]
 * cmd_byte = category<<4 | command<<1
 * checksum = (0xAA - sum(all_bytes)) & 0xFF, or 0x88 for handshake */

/* All-zero PSK (32 bytes) */
#define GOODIX_PSK_LEN 32

/* PSK white box for writing all-zero PSK */
#define GOODIX_PSK_WHITE_BOX_LEN 96

/* GTLS session key material size */
#define GOODIX_SESSION_KEY_LEN 0x44

/* --- Reassembly buffer --- */
typedef struct
{
  guint8 *buf;      /* heap-allocated, GOODIX_RX_BUF_SIZE bytes */
  gsize   len;      /* bytes accumulated */
  gsize   expected; /* total message size from header (including header+checksum) */
  guint8  cmd_byte; /* command byte from first chunk */
} GoodixReassembly;

/* --- GTLS context --- */
typedef struct
{
  gint    state;
  guint8  client_random[32];
  guint8  server_random[32];
  guint8  client_identity[32];
  guint8  server_identity[32];
  guint8  symmetric_key[16];
  guint8  symmetric_iv[16];
  guint8  hmac_key[32];
  guint16 hmac_client_counter_init;
  guint16 hmac_server_counter_init;
  guint32 hmac_client_counter;
  guint32 hmac_server_counter;
  guint8  psk[GOODIX_PSK_LEN];
} GoodixGtlsCtx;

/* --- Calibration parameters (from OTP) --- */
typedef struct
{
  guint16 tcode;
  guint16 delta_fdt;
  guint16 delta_down;
  guint16 delta_up;
  guint16 delta_img;
  guint16 delta_nav;
  guint16 dac_h;
  guint16 dac_l;
  guint16 dac_delta;
  guint8  fdt_base_down[GOODIX_FDT_BASE_LEN];
  guint8  fdt_base_up[GOODIX_FDT_BASE_LEN];
  guint8  fdt_base_manual[GOODIX_FDT_BASE_LEN];
} GoodixCalibParams;

/* --- Command descriptor for sub-SSM --- */
typedef struct
{
  guint8  category;
  guint8  command;
  guint8 *payload;
  gsize   payload_len;
  gboolean use_checksum;

  /* Response storage */
  guint8 *response;
  gsize   response_len;
} GoodixCmd;

/* --- SSM state enums --- */

/* Command sub-SSM */
typedef enum {
  GOODIX_CMD_SEND = 0,
  GOODIX_CMD_RECV_ACK,
  GOODIX_CMD_RECV_DATA,
  GOODIX_CMD_NUM_STATES,
} GoodixCmdState;

/* Open SSM — full device initialization */
typedef enum {
  GOODIX_OPEN_CLAIM_INTERFACE = 0,
  GOODIX_OPEN_EMPTY_BUFFER,
  GOODIX_OPEN_PING,
  GOODIX_OPEN_READ_FW_VERSION,
  GOODIX_OPEN_RESET,
  GOODIX_OPEN_READ_CHIP_ID,
  GOODIX_OPEN_READ_OTP,
  GOODIX_OPEN_PARSE_OTP,
  GOODIX_OPEN_READ_PSK_HASH,
  GOODIX_OPEN_WRITE_PSK,
  GOODIX_OPEN_GTLS_CLIENT_HELLO,
  GOODIX_OPEN_GTLS_RECV_IDENTITY,
  GOODIX_OPEN_GTLS_SEND_VERIFY,
  GOODIX_OPEN_GTLS_RECV_DONE,
  GOODIX_OPEN_UPLOAD_CONFIG,
  GOODIX_OPEN_FDT_TX_ON,
  GOODIX_OPEN_IMAGE_TX_ON,
  GOODIX_OPEN_FDT_TX_OFF,
  GOODIX_OPEN_VALIDATE_FDT,
  GOODIX_OPEN_IMAGE_TX_OFF,
  GOODIX_OPEN_VALIDATE_IMG,
  GOODIX_OPEN_FDT_TX_ON_2,
  GOODIX_OPEN_VALIDATE_FDT_2,
  GOODIX_OPEN_GENERATE_FDT_BASE,
  GOODIX_OPEN_SLEEP,
  GOODIX_OPEN_NUM_STATES,
} GoodixOpenState;

/* Finger-wait SSM (awaiting finger down) */
typedef enum {
  GOODIX_FINGER_WAIT_EC_POWER_ON = 0,
  GOODIX_FINGER_WAIT_FDT_DOWN_SETUP,
  GOODIX_FINGER_WAIT_RECV_EVENT,
  GOODIX_FINGER_WAIT_GEN_UP_BASE,
  GOODIX_FINGER_WAIT_FDT_CHECK,
  GOODIX_FINGER_WAIT_VALIDATE,
  GOODIX_FINGER_WAIT_NUM_STATES,
} GoodixFingerWaitState;

/* Capture SSM */
typedef enum {
  GOODIX_CAPTURE_GET_IMAGE = 0,
  GOODIX_CAPTURE_DECRYPT,
  GOODIX_CAPTURE_DECODE,
  GOODIX_CAPTURE_STORE,
  GOODIX_CAPTURE_NUM_STATES,
} GoodixCaptureState;

/* Finger-up SSM (awaiting finger off) */
typedef enum {
  GOODIX_FINGER_UP_FDT_UP_SETUP = 0,
  GOODIX_FINGER_UP_RECV_EVENT,
  GOODIX_FINGER_UP_UPDATE_DOWN_BASE,
  GOODIX_FINGER_UP_SLEEP,
  GOODIX_FINGER_UP_EC_POWER_OFF,
  GOODIX_FINGER_UP_NUM_STATES,
} GoodixFingerUpState;

/* Deactivate SSM — cleanup after operations */
typedef enum {
  GOODIX_DEACTIVATE_DRAIN = 0,
  GOODIX_DEACTIVATE_SLEEP,
  GOODIX_DEACTIVATE_EC_POWER_OFF,
  GOODIX_DEACTIVATE_NUM_STATES,
} GoodixDeactivateState;

/* Enroll SSM */
typedef enum {
  GOODIX_ENROLL_WAIT_FINGER = 0,
  GOODIX_ENROLL_CAPTURE,
  GOODIX_ENROLL_PROCESS,
  GOODIX_ENROLL_WAIT_FINGER_UP,
  GOODIX_ENROLL_NEXT,
  GOODIX_ENROLL_NUM_STATES,
} GoodixEnrollState;

/* Verify/Identify SSM */
typedef enum {
  GOODIX_VERIFY_WAIT_FINGER = 0,
  GOODIX_VERIFY_CAPTURE,
  GOODIX_VERIFY_MATCH,
  GOODIX_VERIFY_WAIT_FINGER_UP,
  GOODIX_VERIFY_NUM_STATES,
} GoodixVerifyState;

/* --- Device struct --- */
struct _FpiDeviceGoodix53x5
{
  FpDevice parent;

  GCancellable *cancel;

  /* GTLS session (persists across captures) */
  GoodixGtlsCtx gtls;

  /* Calibration (from OTP, persists across captures) */
  GoodixCalibParams calib;

  /* Reassembly buffer for multi-chunk reads */
  GoodixReassembly rx;
  GCancellable    *rx_cancellable; /* Cancellable for current receive */
  guint            rx_timeout;     /* Timeout for current receive continuation */

  /* Temporary data used during SSMs */
  guint16 *calib_image;        /* Background image for subtraction */
  guint8  *fdt_event_data;     /* FDT event data (24 bytes) */
  guint16  fdt_touch_flag;

  /* Temporary FDT data from calibration */
  guint8 *fdt_data_tx_on;
  guint8 *fdt_data_tx_off;
  guint16 *image_tx_on;
  guint16 *image_tx_off;

  /* OTP raw data */
  guint8 *otp_data;
  gsize   otp_len;

  /* Firmware version string */
  gchar *fw_version;

  /* PSK hash for validation */
  guint8 *psk_hash;
  gsize   psk_hash_len;

  /* Current command (for sub-SSM) */
  GoodixCmd *cmd;

  /* Task SSM tracking */
  FpiSsm *task_ssm;

  /* Suspend/resume state */
  gboolean suspended;            /* TRUE between suspend() and resume() calls */
  FpiSsm  *blocking_ssm;        /* Sub-SSM currently blocked on cancellable read */
  int      blocking_resume_state; /* SSM state to jump to on resume */

  /* Captured 8-bit image from last scan */
  guint8 *captured_image;   /* native 108x88 8-bit LCE-processed */

  /* Enrollment tracking */
  GPtrArray *enroll_images; /* array of guint8* native images */
  gint       enroll_stage;
};

/* --- Protocol functions (goodix53x5-proto.c) --- */
guint8  *goodix_proto_build_message (guint8   category,
                                     guint8   command,
                                     const guint8 *payload,
                                     gsize    payload_len,
                                     gboolean use_checksum,
                                     gsize   *out_len);

gboolean goodix_proto_validate_checksum (const guint8 *data,
                                         gsize         len);

void     goodix_proto_rx_reset (GoodixReassembly *rx);
gboolean goodix_proto_rx_feed_chunk (GoodixReassembly *rx,
                                     const guint8     *chunk,
                                     gsize             chunk_len);
gboolean goodix_proto_rx_complete (GoodixReassembly *rx);
gboolean goodix_proto_rx_parse (GoodixReassembly *rx,
                                guint8           *out_category,
                                guint8           *out_command,
                                const guint8    **out_payload,
                                gsize            *out_payload_len);

void goodix_proto_build_mcu_message (guint32       data_type,
                                     const guint8 *data,
                                     gsize         data_len,
                                     guint8      **out_payload,
                                     gsize        *out_payload_len);

gboolean goodix_proto_parse_mcu_message (const guint8 *payload,
                                         gsize         payload_len,
                                         guint32       expected_type,
                                         const guint8 **out_data,
                                         gsize         *out_data_len);

gboolean goodix_proto_parse_production_read (const guint8  *payload,
                                             gsize          payload_len,
                                             guint32        expected_type,
                                             const guint8 **out_data,
                                             gsize         *out_data_len);

/* --- Crypto functions (goodix53x5-crypto.c) --- */
void     goodix_crypto_gtls_init (GoodixGtlsCtx *ctx,
                                  const guint8   *psk);

gboolean goodix_crypto_gtls_derive_keys (GoodixGtlsCtx *ctx);

gboolean goodix_crypto_gtls_verify_identity (GoodixGtlsCtx *ctx);

guint8  *goodix_crypto_gtls_decrypt_sensor_data (GoodixGtlsCtx *ctx,
                                                  const guint8  *encrypted,
                                                  gsize          encrypted_len,
                                                  gsize         *out_len);

void     goodix_crypto_derive_session_key (const guint8 *psk,
                                           gsize         psk_len,
                                           const guint8 *random_data,
                                           gsize         random_len,
                                           guint8       *out_key,
                                           gsize         key_len);

void     goodix_crypto_gea_decrypt (const guint8 *key4,
                                    const guint8 *in,
                                    gsize         in_len,
                                    guint8       *out);

guint32  goodix_crypto_crc32_mpeg2 (const guint8 *data,
                                    gsize         len);

guint32  goodix_crypto_decode_u32 (const guint8 *data);

void     goodix_crypto_aes_cbc_decrypt (const guint8 *key,
                                        const guint8 *iv,
                                        const guint8 *in,
                                        gsize         in_len,
                                        guint8       *out);

void     goodix_crypto_hmac_sha256 (const guint8 *key,
                                    gsize         key_len,
                                    const guint8 *data,
                                    gsize         data_len,
                                    guint8       *out);

/* --- Device helpers (goodix53x5-device.c) --- */
guint8   goodix_device_compute_otp_hash (const guint8 *data,
                                         gsize         len);

gboolean goodix_device_verify_otp (const guint8 *otp,
                                   gsize         otp_len);

void     goodix_device_parse_otp (const guint8      *otp,
                                  gsize              otp_len,
                                  GoodixCalibParams *params);

void     goodix_device_patch_config (guint8              *config,
                                     gsize                config_len,
                                     const GoodixCalibParams *params);

void     goodix_device_fix_config_checksum (guint8 *config,
                                            gsize   config_len);

gboolean goodix_device_is_fdt_base_valid (const guint8 *data1,
                                          const guint8 *data2,
                                          gsize         len,
                                          guint16       max_delta);

void     goodix_device_validate_base_img (const guint16 *img1,
                                          const guint16 *img2,
                                          guint16        threshold,
                                          gboolean      *valid);

void     goodix_device_generate_fdt_base (const guint8 *fdt_data,
                                          gsize         len,
                                          guint8       *fdt_base);

void     goodix_device_generate_fdt_up_base (const guint8        *fdt_data,
                                             guint16              touch_flag,
                                             const GoodixCalibParams *params,
                                             guint8              *fdt_base_up);

guint16 *goodix_device_decode_image (const guint8 *data,
                                     gsize         data_len);

guint8  *goodix_device_image_to_8bit (const guint16 *img12,
                                      const guint16 *calib_img);

const guint8 *goodix_device_get_default_config (gsize *out_len);
