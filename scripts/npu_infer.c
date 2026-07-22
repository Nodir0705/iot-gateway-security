/**
 * npu_infer.c — RK3588 NPU C API inference for IoT Security Gateway
 *
 * Loads classifier.rknn via the rknpu2 C API (librknnrt.so).
 * Exposes a shared library (.so) callable from Python via ctypes.
 *
 * Build:
 *   gcc -O2 -shared -fPIC -o libnpu_infer.so npu_infer.c \
 *       -I$HOME/rknn-toolkit2/rknpu2/runtime/Linux/librknn_api/include \
 *       -lrknnrt -lm
 *
 * Usage from Python:
 *   lib = ctypes.CDLL("./libnpu_infer.so")
 *   lib.npu_init(b"/path/to/classifier.rknn", RKNN_NPU_CORE_0)
 *   lib.npu_infer(input_ptr, output_ptr, n_samples)
 *   lib.npu_destroy()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "rknn_api.h"

/* ─── Feature scaling constants (from scaler.joblib) ─────────────────────── */

#define NUM_FEATURES 13
#define CLIP_VAL     5.0f

static const float SCALER_MEAN[NUM_FEATURES] = {
    7.933816432294374f,
    83.14201921506319f,
    168587.3958689099f,
    22.517945443475938f,
    27.68565403976657f,
    13133.279331185127f,
    4329.685223408521f,
    9451.092150901404f,
    2595.2831925224405f,
    4239466.699111272f,
    49733.26337561743f,
    68444.41542494143f,
    0.9544273346895743f,
};

static const float SCALER_SCALE[NUM_FEATURES] = {
    4.368908220610197f,
    394.91552545320957f,
    1304442.4420431363f,
    54.02568493134367f,
    60.181886847145826f,
    418110.02987959277f,
    65462.3316608453f,
    401655.98277464975f,
    64421.355103819464f,
    33166905.76403522f,
    112560.19780610618f,
    570225.5342492044f,
    0.20855646114893178f,
};

/* ─── Global state ───────────────────────────────────────────────────────── */

static rknn_context    g_ctx = 0;
static int             g_initialized = 0;
static rknn_tensor_attr g_input_attr;
static rknn_tensor_attr g_output_attr;

/* ─── Helper: clamp ──────────────────────────────────────────────────────── */

static inline float clampf(float x, float lo, float hi) {
    return x < lo ? lo : (x > hi ? hi : x);
}

/* ─── Public API ─────────────────────────────────────────────────────────── */

/**
 * npu_init — Load RKNN model and initialize NPU runtime.
 *
 * @param model_path  Path to .rknn file (e.g. "/home/orangepi/iot-gateway/models/classifier.rknn")
 * @param core_mask   NPU core selection (1=core0, 2=core1, 4=core2, 0=auto)
 * @return            0 on success, negative on error
 */
int npu_init(const char *model_path, int core_mask) {
    int ret;

    if (g_initialized) {
        fprintf(stderr, "[npu_infer] already initialized\n");
        return -1;
    }

    /* Load model from file (size=0 means path mode) */
    ret = rknn_init(&g_ctx, (void *)model_path, 0, 0, NULL);
    if (ret != RKNN_SUCC) {
        fprintf(stderr, "[npu_infer] rknn_init failed: %d\n", ret);
        return ret;
    }

    /* Set NPU core affinity */
    ret = rknn_set_core_mask(g_ctx, (rknn_core_mask)core_mask);
    if (ret != RKNN_SUCC) {
        fprintf(stderr, "[npu_infer] rknn_set_core_mask failed: %d (non-fatal)\n", ret);
        /* Non-fatal — continue with default core */
    }

    /* Query I/O attributes */
    rknn_input_output_num io_num;
    ret = rknn_query(g_ctx, RKNN_QUERY_IN_OUT_NUM, &io_num, sizeof(io_num));
    if (ret != RKNN_SUCC) {
        fprintf(stderr, "[npu_infer] query IO num failed: %d\n", ret);
        rknn_destroy(g_ctx);
        return ret;
    }

    memset(&g_input_attr, 0, sizeof(g_input_attr));
    g_input_attr.index = 0;
    ret = rknn_query(g_ctx, RKNN_QUERY_INPUT_ATTR, &g_input_attr, sizeof(g_input_attr));
    if (ret != RKNN_SUCC) {
        fprintf(stderr, "[npu_infer] query input attr failed: %d\n", ret);
        rknn_destroy(g_ctx);
        return ret;
    }

    memset(&g_output_attr, 0, sizeof(g_output_attr));
    g_output_attr.index = 0;
    ret = rknn_query(g_ctx, RKNN_QUERY_OUTPUT_ATTR, &g_output_attr, sizeof(g_output_attr));
    if (ret != RKNN_SUCC) {
        fprintf(stderr, "[npu_infer] query output attr failed: %d\n", ret);
        rknn_destroy(g_ctx);
        return ret;
    }

    /* Print SDK version */
    rknn_sdk_version ver;
    rknn_query(g_ctx, RKNN_QUERY_SDK_VERSION, &ver, sizeof(ver));
    printf("[npu_infer] RKNN C API initialized\n");
    printf("[npu_infer]   API: %s  Driver: %s\n", ver.api_version, ver.drv_version);
    printf("[npu_infer]   Input:  [%u] %s %s  dims=%u\n",
           g_input_attr.index, get_type_string(g_input_attr.type),
           get_format_string(g_input_attr.fmt), g_input_attr.n_dims);
    printf("[npu_infer]   Output: [%u] %s %s  dims=%u  n_elems=%u\n",
           g_output_attr.index, get_type_string(g_output_attr.type),
           get_format_string(g_output_attr.fmt), g_output_attr.n_dims,
           g_output_attr.n_elems);
    printf("[npu_infer]   Core mask: %d\n", core_mask);

    g_initialized = 1;
    return 0;
}

/**
 * npu_scale_features — Apply StandardScaler normalization in-place.
 *
 * @param raw      Pointer to raw feature array (NUM_FEATURES floats per sample)
 * @param scaled   Output buffer (NUM_FEATURES floats per sample)
 * @param n        Number of samples
 */
void npu_scale_features(const float *raw, float *scaled, int n) {
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < NUM_FEATURES; j++) {
            float v = (raw[i * NUM_FEATURES + j] - SCALER_MEAN[j]) / SCALER_SCALE[j];
            scaled[i * NUM_FEATURES + j] = clampf(v, -CLIP_VAL, CLIP_VAL);
        }
    }
}

/**
 * npu_infer — Run inference on pre-scaled features.
 *
 * For the classifier model, output is 2 floats per sample: [normal_logit, attack_logit].
 * Caller applies softmax and argmax.
 *
 * @param input    Scaled float32 features, shape [n, NUM_FEATURES]
 * @param output   Output buffer, shape [n, 2] (caller-allocated)
 * @param n        Number of samples (processed one at a time for static-shape model)
 * @return         0 on success, negative on error
 */
int npu_infer(const float *input, float *output, int n) {
    if (!g_initialized) {
        fprintf(stderr, "[npu_infer] not initialized\n");
        return -1;
    }

    int ret;
    uint32_t out_elems = g_output_attr.n_elems;  /* 2 for classifier */

    for (int i = 0; i < n; i++) {
        /* Set input */
        rknn_input inputs[1];
        memset(inputs, 0, sizeof(inputs));
        inputs[0].index = 0;
        inputs[0].type  = RKNN_TENSOR_FLOAT32;
        inputs[0].fmt   = RKNN_TENSOR_NCHW;
        inputs[0].size  = NUM_FEATURES * sizeof(float);
        inputs[0].buf   = (void *)(input + i * NUM_FEATURES);
        inputs[0].pass_through = 0;

        ret = rknn_inputs_set(g_ctx, 1, inputs);
        if (ret != RKNN_SUCC) {
            fprintf(stderr, "[npu_infer] rknn_inputs_set failed: %d (sample %d)\n", ret, i);
            return ret;
        }

        /* Run */
        ret = rknn_run(g_ctx, NULL);
        if (ret != RKNN_SUCC) {
            fprintf(stderr, "[npu_infer] rknn_run failed: %d (sample %d)\n", ret, i);
            return ret;
        }

        /* Get output (want_float=1 for auto dequantization) */
        rknn_output outputs[1];
        memset(outputs, 0, sizeof(outputs));
        outputs[0].index = 0;
        outputs[0].want_float = 1;
        outputs[0].is_prealloc = 0;

        ret = rknn_outputs_get(g_ctx, 1, outputs, NULL);
        if (ret != RKNN_SUCC) {
            fprintf(stderr, "[npu_infer] rknn_outputs_get failed: %d (sample %d)\n", ret, i);
            return ret;
        }

        /* Copy output logits */
        memcpy(output + i * out_elems, outputs[0].buf, out_elems * sizeof(float));

        /* Release output buffer */
        rknn_outputs_release(g_ctx, 1, outputs);
    }

    return 0;
}

/**
 * npu_infer_classify — Full pipeline: scale + infer + softmax + classify.
 *
 * @param raw_features  Raw (unscaled) float32 features, shape [n, 13]
 * @param results       Output: 0=normal, 1=attack per sample (int array, size n)
 * @param scores        Output: attack probability per sample (float array, size n)
 * @param n             Number of samples
 * @return              0 on success, negative on error
 */
int npu_infer_classify(const float *raw_features, int *results, float *scores, int n) {
    if (!g_initialized) return -1;

    /* Allocate temp buffers */
    float *scaled = (float *)malloc(n * NUM_FEATURES * sizeof(float));
    float *logits = (float *)malloc(n * 2 * sizeof(float));
    if (!scaled || !logits) {
        free(scaled); free(logits);
        return -4;
    }

    /* Scale */
    npu_scale_features(raw_features, scaled, n);

    /* Infer */
    int ret = npu_infer(scaled, logits, n);
    free(scaled);
    if (ret != 0) {
        free(logits);
        return ret;
    }

    /* Softmax + classify */
    for (int i = 0; i < n; i++) {
        float l0 = logits[i * 2 + 0];  /* normal logit */
        float l1 = logits[i * 2 + 1];  /* attack logit */
        float max_l = l0 > l1 ? l0 : l1;
        float e0 = expf(l0 - max_l);
        float e1 = expf(l1 - max_l);
        float sum = e0 + e1;
        float p_attack = e1 / sum;

        results[i] = (p_attack > 0.5f) ? 1 : 0;
        scores[i]  = p_attack;
    }

    free(logits);
    return 0;
}

/**
 * npu_get_output_elems — Return the number of output elements per sample.
 */
int npu_get_output_elems(void) {
    return g_initialized ? (int)g_output_attr.n_elems : 0;
}

/**
 * npu_destroy — Release RKNN context and free resources.
 */
void npu_destroy(void) {
    if (g_initialized) {
        rknn_destroy(g_ctx);
        g_ctx = 0;
        g_initialized = 0;
        printf("[npu_infer] RKNN context destroyed\n");
    }
}
