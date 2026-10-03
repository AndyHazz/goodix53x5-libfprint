/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Internal synthetic-only observer. ABI belongs to the launcher-pinned x64 DLL.
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../test-goodix53x5-milan-native-match-format.h"

typedef int (*init_fn) (int);
typedef int (*version_fn) (char *);
typedef int (*calib_init_fn) (void);
typedef int (*calib_get_fn) (void **,
                             uint32_t *);
typedef int (*unpack_fn) (const void *,
                          int,
                          void *,
                          void **);
typedef int (*size_fn) (void *);
typedef int (*pack_fn) (void *,
                        void *);
typedef void (*delete_fn) (void *);
typedef int (*match_fn) (int *,
                         void *,
                         void *,
                         int,
                         int,
                         void *,
                         void *,
                         void *);

static void
require (int ok, const char *operation)
{
  if (!ok)
    {
      fprintf (stderr, "native match: %s failed\n", operation);
      exit (1);
    }
}

static void
resolve (HMODULE module, const char *name, void *destination, size_t size)
{
  FARPROC result = GetProcAddress (module, name);

  require (result != NULL && size == sizeof (result), name);
  memcpy (destination, &result, size);
}

static void *
read_template (const wchar_t *path, unpack_fn unpack)
{
  FILE *file = _wfopen (path, L"rb");
  void *object = NULL;

  require (file != NULL, "open synthetic input");
  require (fseek (file, 0, SEEK_END) == 0, "seek input");
  long size = ftell (file);
  require (size > 0 && size <= 4 * 1024 * 1024, "input size");
  rewind (file);
  void *data = malloc ((size_t) size);
  require (data != NULL, "allocate input");
  require (fread (data, 1, size, file) == (size_t) size, "read input");
  require (fclose (file) == 0, "close input");
  require (unpack (data, (int) size, NULL, &object) == 0 && object != NULL,
           "templateUnPack");
  free (data);
  return object;
}

static void
save (const wchar_t *path, const void *data, size_t size)
{
  FILE *file = _wfopen (path, L"wb");

  require (file != NULL, "open output");
  require (fwrite (data, 1, size, file) == size, "write output");
  require (fclose (file) == 0, "close output");
}

int
wmain (int argc, wchar_t **argv)
{
  require (argc == 6, "internal arguments");
  HMODULE module = LoadLibraryW (argv[1]);
  require (module != NULL, "LoadLibrary");
  init_fn init;
  version_fn version;
  calib_init_fn calib_init;
  calib_get_fn calib_get;
  unpack_fn unpack;
  size_fn get_size;
  pack_fn pack;
  delete_fn destroy;
  resolve (module, "ppp_param_init", &init, sizeof (init));
  resolve (module, "getAlgorithmVersion", &version, sizeof (version));
  resolve (module, "preprocess_init_calidata", &calib_init, sizeof (calib_init));
  resolve (module, "preprocessor_get_CalibParam", &calib_get, sizeof (calib_get));
  resolve (module, "templateUnPack", &unpack, sizeof (unpack));
  resolve (module, "templateGetPackedSize", &get_size, sizeof (get_size));
  resolve (module, "templatePack", &pack, sizeof (pack));
  resolve (module, "templateDelete", &destroy, sizeof (destroy));
  char algorithm_version[128] = { 0 };
  void *calibration = NULL;
  uint32_t calibration_size = 0;
  require (version (algorithm_version) == 0, "getAlgorithmVersion");
  require (init (9) == 0 && calib_init () == 0, "profile 9 initialization");
  require (calib_get (&calibration, &calibration_size) == 0 && calibration &&
           calibration_size, "calibration parameters");
  void *probe = read_template (argv[2], unpack);
  void *gallery = read_template (argv[3], unpack);
  uint8_t *g = *(uint8_t **) gallery;
  uint8_t *p_owner = *(uint8_t **) probe;
  require (g && p_owner, "unpacked owners");
  void *p = *(void **) (p_owner + 0x28);
  require (p != NULL && *(int32_t *) g == 12, "type-12 matcher boundary");
  match_fn match = (match_fn) ((uint8_t *) module + 0x5edb0);
  int evidence[0x698 / 4] = { 0 }, relation[9] = { 0 }, score = 0;
  int status = match (&score, p, g, 0, 1, evidence, relation, NULL);
  require (status == 0, "matcher status");

  /* Observe returned evidence before packing. No gates or decisions injected. */
  uint8_t observed[NATIVE_MATCH_OBSERVATION_SIZE];
  int32_t words[NATIVE_MATCH_WORDS] = {
    status, score, evidence[0x648 / 4], evidence[0x668 / 4],
  };
  memcpy (words + 4, evidence + 0x650 / 4, 6 * sizeof (int32_t));
  memcpy (words + 10, evidence + 0x66c / 4, 6 * sizeof (int32_t));
  memcpy (words + 16, g + 0x8db0, NATIVE_MATCH_QUEUE_SLOTS * sizeof (int32_t));
  for (size_t i = 0; i < NATIVE_MATCH_WORDS; i++)
    native_match_put_u32 (observed + 4 * i, (uint32_t) words[i]);
  save (argv[5], observed, sizeof (observed));

  int size = get_size (gallery);
  require (size > 0 && size <= 4 * 1024 * 1024, "templateGetPackedSize");
  void *packed = malloc ((size_t) size);
  require (packed != NULL, "allocate packed output");
  require (pack (gallery, packed) == 0, "templatePack");
  save (argv[4], packed, (size_t) size);
  printf ("algorithm=%s status=%d score=%d winner=%d relation-count=%d size=%d\n",
          algorithm_version, status, score, words[2], words[3], size);
  free (packed);
  destroy (gallery);
  destroy (probe);
  FreeLibrary (module);
  return 0;
}
