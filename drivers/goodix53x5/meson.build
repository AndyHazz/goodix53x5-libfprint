goodix53x5_sources = files(
    'milan/antifake/classifier.c',
    'milan/antifake/construction.c',
    'milan/antifake/feature.c',
    'milan/antifake/mask.c',
    'milan/antifake/morphology.c',
    'milan/antifake/pair.c',
    'milan/antifake/signal.c',
    'device/auth.c',
    'device/base.c',
    'device/calibration.c',
    'device/commands.c',
    'device/crypto.c',
    'device/enroll.c',
    'device/health.c',
    'milan/enrollment/propagation.c',
    'milan/enrollment/template.c',
    'milan/feature/enhancement.c',
    'milan/feature/extraction.c',
    'milan/feature/extrema.c',
    'milan/feature/mask.c',
    'milan/feature/materialization.c',
    'milan/feature/record.c',
    'device/image.c',
    'device/persistence.c',
    'milan/match/admission.c',
    'milan/match/candidate.c',
    'milan/match/correspondence.c',
    'milan/match/fallback.c',
    'milan/match/geometry.c',
    'milan/match/info.c',
    'milan/match/lifecycle.c',
    'milan/match/overlap.c',
    'milan/match/policy.c',
    'milan/match/rescue.c',
    'milan/match/score.c',
    'milan/match/selection.c',
    'milan/match/study.c',
    'milan/match/match.c',
    'milan/core.c',
    'milan/debug-hooks.c',
    'milan/preprocess/classification.c',
    'milan/preprocess/gain.c',
    'milan/preprocess/selection.c',
    'milan/preprocess/validity.c',
    'milan/print.c',
    'device/proto.c',
    'milan/relations.c',
    'milan/runtime.c',
    'device/scan.c',
    'device/session.c',
    'milan/study/policy.c',
    'milan/study/queue.c',
    'milan/study/study.c',
    'milan/template/codec.c',
    'milan/template/lifecycle.c',
    'milan/transform.c',
    'device/transport.c',
    'goodix53x5.c',
)

goodix53x5_cflags = [ '-I' + meson.current_source_dir() ]
if 'goodix53x5' in drivers
    optional_deps += dependency('libdeflate')
endif
if get_option('goodix53x5_debug')
    goodix53x5_debug_build_id = get_option('goodix53x5_debug_build_id')
    goodix53x5_debug_source_id = get_option('goodix53x5_debug_source_id')
    if goodix53x5_debug_build_id == ''
        error('goodix53x5_debug requires goodix53x5_debug_build_id')
    endif
    if goodix53x5_debug_source_id == ''
        error('goodix53x5_debug requires goodix53x5_debug_source_id')
    endif
    goodix53x5_sources += files('device/debug.c')
    goodix53x5_cflags += [
        '-DGOODIX53X5_DEBUG',
        '-DGOODIX53X5_DEBUG_BUILD_ID="' + goodix53x5_debug_build_id + '"',
        '-DGOODIX53X5_DEBUG_SOURCE_ID="' + goodix53x5_debug_source_id + '"',
    ]
endif
