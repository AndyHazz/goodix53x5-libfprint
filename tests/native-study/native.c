/* SPDX-License-Identifier: LGPL-2.1-or-later
 * Private subprocess of generate.py, for its freshly generated synthetic inputs.
 * ABI addresses are specific to the hash pinned by that launcher (x64 only).
 */
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
typedef int (*study_fn) (void *,
                         void *,
                         const int *,
                         int *,
                         int);

static void
require (int ok, const char *operation)
{
  if (!ok)
    {
      fprintf (stderr, "native study: %s failed\n", operation);
      exit (1);
    }
}

static void
resolve (HMODULE module, const char *name, void *destination, size_t size)
{
  FARPROC result = GetProcAddress (module, name);

  require (result != NULL, name);
  require (size == sizeof (result), "x64 function pointer size");
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
save_template (const wchar_t *path, void *object, size_fn get_size, pack_fn pack)
{
  int size = get_size (object);

  require (size > 0 && size <= 4 * 1024 * 1024, "templateGetPackedSize");
  void *data = malloc ((size_t) size);
  require (data != NULL, "allocate packed output");
  require (pack (object, data) == 0, "templatePack");
  FILE *file = _wfopen (path, L"wb");
  require (file != NULL, "open output");
  require (fwrite (data, 1, size, file) == (size_t) size, "write packed output");
  require (fclose (file) == 0, "close output");
  free (data);
}

int
wmain (int argc, wchar_t **argv)
{
  require (argc == 7, "internal arguments");
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
  require (init (9) == 0, "profile 9 initialization");
  require (calib_init () == 0, "calibration initialization");
  require (calib_get (&calibration, &calibration_size) == 0 &&
           calibration != NULL && calibration_size > 0, "calibration parameters");
  void *probe = read_template (argv[2], unpack);
  void *gallery = read_template (argv[3], unpack);
  void *g = *(void **) gallery;
  void *p_owner = *(void **) probe;
  require (g != NULL && p_owner != NULL, "unpacked owners");
  void *p = *(void **) ((uint8_t *) p_owner + 0x28);
  require (p != NULL, "probe feature");
  match_fn match = (match_fn) ((uint8_t *) module + 0x5edb0);
  study_fn study = (study_fn) ((uint8_t *) module + 0x44fc0);
  int evidence[0x698 / 4] = { 0 }, relation[9] = { 0 }, score = 0;
  int result[2] = { 0, -1 };
  require (match (&score, p, g, 0, 1, evidence, relation, NULL) == 0, "matcher");
  require (score == 100 && evidence[0x648 / 4] == 2 &&
           evidence[0x644 / 4] == 1 && evidence[0x684 / 4] == 1 &&
           evidence[0x688 / 4] == 1, "natural match outcomes");
  save_template (argv[4], gallery, get_size, pack);
  /* Exactly the returned evidence and same mutated gallery; no injected gates. */
  require (study (g, p, evidence, result, 1) == 0, "study");
  require (result[0] == 4 && result[1] == _wtoi (argv[6]), "natural study outcomes");
  save_template (argv[5], gallery, get_size, pack);
  printf ("algorithm=%s score=%d winner=%d action=%d selected=%d\n",
          algorithm_version, score, evidence[0x648 / 4], result[0], result[1]);
  destroy (gallery);
  destroy (probe);
  FreeLibrary (module);
  return 0;
}
