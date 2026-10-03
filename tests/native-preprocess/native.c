/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Approved DLL observer. Inputs are supplied only by the synthetic launcher.
 * No current driver code, classifier decisions, or expected-output calculation.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include "../test-goodix53x5-milan-native-preprocess-format.h"

typedef struct
{
  uint8_t         reserved[0x18];
  const uint16_t *frame;
  uint32_t        unused, rows, columns;
} Setup;

typedef struct
{
  void    *data;
  uint8_t  format[12];
  uint32_t capacity;
  uint16_t valid, reserved_1a;
  int32_t  purpose;
  uint8_t  reserved_20[8];
  uint8_t  quality, coverage, reserved_2a[6];
} Image;

typedef struct
{
  int32_t count, rows, columns, reserved;
  uint8_t pixels[NP_PIXELS];
} Mask;

typedef int32_t (*InitProfile) (int32_t);
typedef int32_t (*NoArgs) (void);
typedef int32_t (*GetCalibration) (void **,
                                   uint32_t *);
typedef int32_t (*Init) (const Setup *);
typedef int32_t (*Preprocess) (const Image *,
                               const int32_t *,
                               void *,
                               Image *,
                               int32_t *,
                               uint8_t,
                               uint8_t);
typedef int32_t (*Publish) (const uint16_t *,
                            void *,
                            uint32_t,
                            Mask *,
                            int32_t *,
                            int32_t *,
                            uint8_t *,
                            uint8_t *,
                            int32_t);

_Static_assert (offsetof (Setup, frame) == 0x18, "setup frame ABI");
_Static_assert (offsetof (Setup, rows) == 0x24, "setup dimensions ABI");
_Static_assert (offsetof (Image, purpose) == 0x1c, "image purpose ABI");
_Static_assert (offsetof (Image, quality) == 0x28, "image quality ABI");
_Static_assert (offsetof (Mask, pixels) == 0x10, "mask ABI");

static void
require (int condition, const char *message)
{
  if (!condition)
    {
      fprintf (stderr, "%s (Windows error %lu)\n", message, GetLastError ());
      exit (2);
    }
}

static void
symbol (HMODULE module, const char *name, void *destination, size_t size)
{
  FARPROC address = GetProcAddress (module, name);

  require (address != NULL && size == sizeof (address), name);
  memcpy (destination, &address, size);
}

static uint32_t
native_u32 (const void *p)
{
  uint32_t value;

  memcpy (&value, p, sizeof (value));
  return value;
}

int
wmain (int argc, wchar_t **argv)
{
  require (argc == 5, "usage: native.exe DLL CASE INPUT OUTPUT (internal launcher only)");
  int natural = wcscmp (argv[2], L"natural") == 0;
  require (natural || wcscmp (argv[2], L"temporal-800") == 0 ||
           wcscmp (argv[2], L"temporal-0") == 0, "unknown case");
  size_t input_size = NP_INPUT_BYTES + (natural ? 0 : NP_PIXELS);
  uint8_t input[NP_INPUT_BYTES + NP_PIXELS];
  FILE *file = _wfopen (argv[3], L"rb");
  require (file != NULL, "input open");
  require (fread (input, 1, input_size, file) == input_size &&
           fgetc (file) == EOF && !ferror (file), "input length/trailing bytes");
  require (fclose (file) == 0, "input close");
  uint16_t frames[3][NP_PIXELS];
  for (unsigned int frame = 0; frame < 3; frame++)
    for (size_t i = 0; i < NP_PIXELS; i++)
      frames[frame][i] = np_read16 (input + frame * NP_FRAME_BYTES + 2 * i);

  HMODULE module = LoadLibraryW (argv[1]);
  require (module != NULL, "DLL load");
  uint8_t *base = (uint8_t *) module;
  InitProfile profile;
  NoArgs reset, finish;
  GetCalibration get_calibration;
  Init init;
  Preprocess preprocess;
  symbol (module, "ppp_param_init", &profile, sizeof (profile));
  symbol (module, "preprocess_init_calidata", &reset, sizeof (reset));
  symbol (module, "preprocessor_exit", &finish, sizeof (finish));
  symbol (module, "preprocessor_get_CalibParam", &get_calibration, sizeof (get_calibration));
  symbol (module, "preprocessor_init", &init, sizeof (init));
  symbol (module, "preprocessor", &preprocess, sizeof (preprocess));
  Publish publish = (Publish) (base + 0x6b290);
  void *calibration = NULL;
  uint32_t calibration_size = 0;
  require (profile (9) == 0 && reset () == 0, "profile9 initialization");
  require (get_calibration (&calibration, &calibration_size) == 0 &&
           calibration != NULL && calibration_size >= 4, "calibration owner");
  uint8_t *workspace = calloc (1, 0x3048c);
  uint8_t *auxiliary = calloc (1, 0x4c98);
  require (workspace && auxiliary, "workspace allocation");
  if (natural)
    {
      Setup setup = { 0 };
      setup.frame = frames[0];
      setup.rows = 88;
      setup.columns = 108;
      require (init (&setup) == 0, "native setup admission");
    }
  else
    {
      memcpy (workspace + 0x9924, frames[0], NP_FRAME_BYTES);
    }

  file = _wfopen (argv[4], L"wb");
  require (file != NULL, "output open");
  unsigned int calls = natural ? 24 : 22;
  for (unsigned int call = 1; call <= calls; call++)
    {
      uint16_t live[NP_PIXELS];
      uint8_t pixels[NP_PIXELS] = { 0 };
      uint8_t record[NP_NATURAL_RECORD_BYTES];
      int32_t status, first = 0, second = 0;
      memcpy (live, frames[call >= (natural ? 23 : 22) ? 2 : 1], sizeof (live));
      memset (auxiliary, 0, 0x4c98);
      if (natural)
        {
          Image source = { 0 }, result = { 0 };
          int32_t purpose = 0, coverage_quality[2] = { 0 };
          source.data = live;
          source.format[6] = 0x10;
          source.format[7] = 1;
          source.capacity = NP_FRAME_BYTES;
          source.valid = 1;
          result.data = pixels;
          result.format[0] = 108;
          result.format[2] = 88;
          result.format[6] = 8;
          result.format[7] = 1;
          result.capacity = NP_PIXELS;
          result.valid = 1;
          status = preprocess (&source, &purpose, auxiliary, &result,
                               coverage_quality, 0, 0);
          first = coverage_quality[1]; /* Native pair is coverage, quality. */
          second = coverage_quality[0];
          require (status == 0 || status == 0x7531, "unexpected natural status");
          require (result.data == pixels && result.capacity == NP_PIXELS &&
                   result.quality == first && result.coverage == second,
                   "exported descriptor publication");
        }
      else
        {
          Mask mask = { NP_PIXELS, 88, 108, 0, { 0 } };
          memcpy (mask.pixels, input + NP_INPUT_BYTES, NP_PIXELS);
          /* Valid caller boundary, not imported classifier history. */
          memcpy (workspace, &call, sizeof (uint32_t));
          status = publish (live, workspace, 0x36160061, &mask, &second,
                            &first, pixels, auxiliary, 0);
          require (status == 0 || status == 0xc351, "unexpected temporal status");
        }
      np_write32 (record, (uint32_t) status);
      np_write32 (record + 4, (uint32_t) first);
      np_write32 (record + 8, (uint32_t) second);
      memcpy (record + 12, auxiliary, 3);
      memcpy (record + 15, pixels, NP_PIXELS);
      size_t offset = 15 + NP_PIXELS;
      if (natural)
        {
          np_write32 (record + offset, native_u32 (calibration));
          offset += 4;
        }
      np_write32 (record + offset, native_u32 (base + 0x1dc9a4));
      offset += 4;
      np_write_words (record + offset, (const uint16_t *) (base + 0x1dc9b0));
      offset += NP_FRAME_BYTES;
      memcpy (record + offset, base + 0x1e62d0, NP_PIXELS);
      offset += NP_PIXELS;
      require (fwrite (record, 1, offset, file) == offset, "complete output write");
      printf ("call=%u status=%d %s=%d %s=%d history=%u\n", call, status,
              natural ? "quality" : "mode", first,
              natural ? "coverage" : "apply", second, native_u32 (base + 0x1dc9a4));
    }
  require (fclose (file) == 0, "output close");
  require (finish () == 0, "preprocessor teardown");
  free (workspace);
  free (auxiliary);
  require (FreeLibrary (module), "DLL unload");
  return 0;
}
