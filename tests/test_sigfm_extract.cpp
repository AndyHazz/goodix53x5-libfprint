// Host-side unit tests for sigfm_extract() robustness. No sensor needed.
//
// sigfm_extract() is called across the C ABI from the driver's C state-machine
// handlers (goodix53x5-auth.c, goodix53x5-enroll.c, via goodix_match_extract()).
// A C++ exception unwinding out of it and through a C stack frame is undefined
// behaviour and reaches std::terminate(), taking the root fprintd process with
// it - an authentication denial of service. See issue #22.
//
// These tests pin the exported contract: sigfm_extract() reports failure by
// returning nullptr and never lets an exception escape, and the accessors the C
// callers reach for next tolerate that nullptr. Each hostile case runs in a
// forked child because the pre-fix failure modes are fatal signals (SIGABRT
// from std::terminate, SIGSEGV from a null dereference) that would otherwise
// take the whole test binary down.
//
// Build and run from the repo root (OpenCV 5 names the features2d library
// opencv_features, OpenCV 4 names it opencv_features2d):
//
//   g++ -std=c++17 tests/test_sigfm_extract.cpp sigfm/sigfm.cpp
//     $(pkg-config --cflags opencv5 2>/dev/null || pkg-config --cflags opencv4)
//     -lopencv_core -lopencv_imgproc -lopencv_flann
//     $(pkg-config --exists opencv5 && echo -lopencv_features
//       || echo -lopencv_features2d)
//     -o /tmp/test_sigfm_extract
//   /tmp/test_sigfm_extract
//
// (join those continuation lines into one command)

#include "../sigfm/sigfm.hpp"

#include <cstdio>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

static int failures = 0;

#define CHECK(cond, msg)                                                       \
  do {                                                                         \
    if (!(cond)) {                                                             \
      std::printf("  FAIL: %s\n", msg);                                        \
      failures++;                                                              \
    } else {                                                                   \
      std::printf("  ok:   %s\n", msg);                                        \
    }                                                                          \
  } while (0)

// Run `body` in a child process and pass only if it exits 0. A child killed by a
// signal, or exiting non-zero, is a failure - that is how the pre-fix
// std::terminate() and null-dereference cases surface.
template <typename F>
static void check_survives(const char *msg, F body)
{
  pid_t pid = fork();

  if (pid == 0) {
    _exit(body() ? 0 : 1);
  }

  if (pid < 0) {
    std::printf("  FAIL: could not fork for: %s\n", msg);
    failures++;
    return;
  }

  int status = 0;
  waitpid(pid, &status, 0);

  if (WIFSIGNALED(status)) {
    std::printf("  FAIL: %s (child killed by signal %d)\n", msg,
                WTERMSIG(status));
    failures++;
    return;
  }

  CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, msg);
}

// Dimensions the driver actually uses (GOODIX_SENSOR_WIDTH/HEIGHT).
static const int kWidth = 108;
static const int kHeight = 88;

// Current address-space size, so the allocation-failure test can set a limit
// just above it and starve only the allocation under test.
static std::size_t vm_size_kb()
{
  FILE *f = std::fopen("/proc/self/status", "r");
  char line[256];
  std::size_t kb = 0;

  if (f == nullptr) {
    return 0;
  }
  while (std::fgets(line, sizeof line, f) != nullptr) {
    if (std::sscanf(line, "VmSize: %zu kB", &kb) == 1) {
      break;
    }
  }
  std::fclose(f);
  return kb;
}

int main()
{
  // A mid-grey frame of the real sensor size: valid input, must keep working.
  std::vector<SigfmPix> frame(kWidth * kHeight, 128);

  // Pre-fix, an empty image threw cv::Exception out of SIFT::detectAndCompute
  // and reached std::terminate() through the C ABI.
  check_survives("zero dimensions return nullptr", [&] {
    return sigfm_extract(frame.data(), 0, 0) == nullptr;
  });

  // Worse than the zero case: cv::Mat::create() accepts negative dimensions
  // without throwing, so the memcpy runs against a broken Mat and corrupts the
  // heap. The throw only surfaces later inside CLAHE, by which point unwinding
  // itself segfaults in free(). Only an up-front dimension check avoids this -
  // the try/catch alone converts SIGABRT into SIGSEGV.
  check_survives("negative dimensions return nullptr", [&] {
    return sigfm_extract(frame.data(), -1, -1) == nullptr;
  });

  // The scenario issue #22 identifies as the realistic trigger: an allocation
  // failure with otherwise valid input. Clamp the child's address space so
  // OpenCV's allocation for a large image fails, and check the resulting
  // exception is contained rather than escaping to std::terminate(). This is
  // the case that exercises the try/catch itself - the dimension checks above
  // are rejected before OpenCV is ever called.
  check_survives("allocation failure returns nullptr, no exception escapes", [] {
    const int big = 4000;
    // Allocate the source buffer before clamping, so only OpenCV is starved.
    std::vector<SigfmPix> buf((std::size_t) big * big, 128);
    std::size_t limit = (vm_size_kb() + 4096) * 1024;
    struct rlimit rl = {limit, limit};

    if (setrlimit(RLIMIT_AS, &rl) != 0) {
      return false;
    }
    return sigfm_extract(buf.data(), big, big) == nullptr;
  });

  // Not an exception - the memcpy dereferences pix directly, so this needs its
  // own guard rather than the try/catch.
  check_survives("null pixel buffer returns nullptr", [&] {
    return sigfm_extract(nullptr, kWidth, kHeight) == nullptr;
  });

  // The C callers pass sigfm_extract()'s result straight to
  // goodix_match_keypoints_count() (goodix53x5-match.c) before any null check,
  // so returning nullptr is only safe if the accessor tolerates it. Without
  // this, the fix just swaps std::terminate() for a segfault.
  check_survives("keypoints_count(nullptr) returns 0", [&] {
    return sigfm_keypoints_count(nullptr) == 0;
  });

  // Regression guard: real sensor-sized input still extracts normally.
  SigfmImgInfo *info = sigfm_extract(frame.data(), kWidth, kHeight);
  CHECK(info != nullptr, "valid sensor-sized frame still extracts");
  if (info != nullptr) {
    // A flat grey frame has no SIFT features; the point is that the call
    // completes and the count is readable, not that it finds anything.
    CHECK(sigfm_keypoints_count(info) >= 0,
          "valid frame reports a readable keypoint count");
    sigfm_free_info(info);
  }

  if (failures == 0) {
    std::printf("\nALL TESTS PASSED\n");
    return 0;
  }
  std::printf("\n%d TEST(S) FAILED\n", failures);
  return 1;
}
