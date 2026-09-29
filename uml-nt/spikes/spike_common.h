/* uml-nt M0 spikes — shared helpers (Windows side). PL shorthand. */
#ifndef SPIKE_COMMON_H
#define SPIKE_COMMON_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static LARGE_INTEGER sc_freq;

static void sc_init(void) { QueryPerformanceFrequency(&sc_freq); }

static inline int64_t sc_now(void) {
    LARGE_INTEGER t; QueryPerformanceCounter(&t); return t.QuadPart;
}
static inline double sc_ns(int64_t ticks) {
    return (double)ticks * 1e9 / (double)sc_freq.QuadPart;
}

static int sc_cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

/* sorts v[] in place, writes a JSON object with percentiles */
static void sc_stats(FILE *f, const char *key, double *v, int n) {
    double s = 0.0;
    for (int i = 0; i < n; i++) s += v[i];
    qsort(v, n, sizeof(double), sc_cmp);
    fprintf(f,
        "\"%s\": {\"p50_ns\": %.0f, \"p90_ns\": %.0f, \"p99_ns\": %.0f, \"avg_ns\": %.0f, \"n\": %d}",
        key, v[(int)(0.50 * (n - 1))], v[(int)(0.90 * (n - 1))],
        v[(int)(0.99 * (n - 1))], s / n, n);
}

#endif
