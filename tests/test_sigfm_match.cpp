// Host-side unit tests for sigfm_match_score().
//
// These do NOT need the sensor. They construct SigfmImgInfo directly with
// controlled keypoints + descriptors so descriptor matching is 1:1 and the
// *geometry* alone decides the score. This exercises the contract of the
// pairwise-geometric matcher: a probe whose keypoints are a single consistent
// transform of the enrolled keypoints (a genuine re-press of the same finger)
// scores high, geometrically unrelated keypoints score low, and too few
// correspondences reject.
//
// NOTE on scope: real-world impostor rejection on this sensor depends mainly on
// PREPROCESSING (a different finger produces different SIFT descriptors, so the
// correspondences never form in the first place), not on the geometric scorer
// alone. These tests force 1:1 descriptor matches to isolate the scorer, so
// they validate the geometry contract, not the end-to-end false-accept rate
// (that is measured on-device; see the README).
//
// Build (run from the repo root):
//   g++ -std=c++17 tests/test_sigfm_match.cpp sigfm/sigfm.cpp \
//       -I/usr/include/opencv4 \
//       -lopencv_core -lopencv_features2d -lopencv_imgproc -lopencv_flann \
//       -o /tmp/test_sigfm && /tmp/test_sigfm

#include "../sigfm/img-info.hpp"
#include "../sigfm/sigfm.hpp"

#include <cmath>
#include <cstdio>
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

// Build an info with one-hot descriptors so frame[i] uniquely matches
// enrolled[i] (distance 0, easily passes Lowe's ratio test). Geometry is
// entirely controlled by the supplied keypoint positions.
static SigfmImgInfo *make_info(const std::vector<cv::Point2f> &pts)
{
  auto *info = new SigfmImgInfo();
  const int n = static_cast<int>(pts.size());
  info->descriptors = cv::Mat::zeros(n, n, CV_32F);
  for (int i = 0; i < n; i++)
    {
      info->keypoints.emplace_back(pts[i], 1.0f);
      info->descriptors.at<float>(i, i) = 1.0f;
    }
  return info;
}

// A rigid transform (rotation + translation, no scale), the kind a genuine
// re-press of the same finger produces.
static cv::Point2f transformA(const cv::Point2f &p)
{
  const double th = 5.0 * M_PI / 180.0;
  const double c = std::cos(th), s = std::sin(th);
  return cv::Point2f(static_cast<float>(c * p.x - s * p.y + 4.0),
                     static_cast<float>(s * p.x + c * p.y + 3.0));
}

int main()
{
  // Enrolled: 40 keypoints spread across the 108x88 sensor area.
  std::vector<cv::Point2f> enr;
  for (int i = 0; i < 40; i++)
    enr.emplace_back(10.0f + (i * 37) % 88, 10.0f + (i * 53) % 68);

  // ---- Genuine: every correspondence fits ONE transform ----
  std::vector<cv::Point2f> genuine;
  for (const auto &p : enr)
    genuine.push_back(transformA(p));

  // ---- Non-match: keypoints with no consistent geometric relationship to the
  // enrolled set (different finger). Pairwise lengths/angles disagree, so the
  // scorer should find few mutually-consistent correspondences. ----
  std::vector<cv::Point2f> scattered;
  for (int i = 0; i < 40; i++)
    scattered.emplace_back(4.0f + (i * 61 + 13) % 100,
                           4.0f + (i * 29 + 7) % 80);

  SigfmImgInfo *e = make_info(enr);
  SigfmImgInfo *g = make_info(genuine);
  SigfmImgInfo *nm = make_info(scattered);

  int sg = sigfm_match_score(g, e);
  int sn = sigfm_match_score(nm, e);
  std::printf("genuine score = %d, non-match score = %d\n", sg, sn);

  // Genuine: all correspondences share one transform -> many mutually
  // consistent pairs -> very high score.
  CHECK(sg >= 1000, "genuine (single consistent transform) scores high");
  // Separation is the scorer's real contract: a single consistent transform
  // scores orders of magnitude above geometrically-unrelated correspondences.
  //
  // NOTE: we deliberately do NOT assert sn < GOODIX_SIGFM_BEST_MIN. With
  // descriptor matching forced 1:1, even unrelated geometry can produce a
  // handful of coincidentally-consistent pairs and clear the runtime gate.
  // Real impostor rejection comes from preprocessing (a different finger yields
  // different descriptors, so these correspondences never form), not from the
  // geometric scorer bounding unrelated input. This test isolates the scorer,
  // so it asserts separation, not an absolute non-match ceiling.
  CHECK(sg > sn * 100, "genuine scores orders of magnitude above a non-match");

  sigfm_free_info(g);
  sigfm_free_info(nm);

  // ---- Degenerate: too few correspondences must reject (return 0). With
  // fewer than the matcher's minimum consistent-pair count, score is 0. ----
  std::vector<cv::Point2f> few = {{10, 10}, {20, 20}, {30, 30}};
  SigfmImgInfo *e2 = make_info(few);
  SigfmImgInfo *f2 = make_info(few);
  int sf = sigfm_match_score(f2, e2);
  std::printf("too-few-keypoints score = %d\n", sf);
  CHECK(sf == 0, "too few correspondences rejects (score 0)");
  sigfm_free_info(e2);
  sigfm_free_info(f2);
  sigfm_free_info(e);

  if (failures == 0)
    {
      std::printf("\nALL TESTS PASSED\n");
      return 0;
    }
  std::printf("\n%d TEST(S) FAILED\n", failures);
  return 1;
}
