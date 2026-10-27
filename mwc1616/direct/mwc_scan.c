/* Exhaustive first-component MWC1616 projection search.
 *
 * Usage: mwc_scan MULTIPLIER BITS UNITS_CSV BEGIN END [MAX_STORED]
 * All arguments and CSV units are unsigned decimal integers. BITS is 4 or 8;
 * BEGIN and END form a half-open interval in [0, 2^(32-BITS)].
 *
 * For x = a * (previous & 65535) + (previous >> 16), the combined MWC output
 * is (x << 16) | (other & 65535), reduced to uint32. Its top BITS therefore
 * observe bits [16-BITS, 15] of x, independently of the other component.
 *
 * Fixing the first observed unit leaves exactly 32-BITS freely chosen bits.
 * The unranking below inserts that unit into the omitted bit positions, so
 * every uint32 first-observed state satisfying it occurs exactly once. The
 * scan intentionally admits arbitrary uint32 states, including noncanonical
 * or invalid browser seeds. Failure of every candidate is thus an exclusion
 * for the supplied consecutive full observations without a seed assumption.
 * No inference is made about partial units omitted by the caller.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_UNITS 256

static int parse_decimal(const char *text, uint64_t *value)
{
    const unsigned char *p = (const unsigned char *)text;
    if (*p == '\0') return 0;
    for (; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') return 0;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT64_MAX) return 0;
    *value = (uint64_t)parsed;
    return 1;
}

/* Parse directly; strtok would silently accept empty or trailing fields. */
static int parse_units(const char *text, uint32_t limit,
                       uint32_t units[MAX_UNITS], size_t *count)
{
    const unsigned char *p = (const unsigned char *)text;
    size_t used = 0;
    for (;;) {
        if (*p < '0' || *p > '9' || used == MAX_UNITS) return 0;
        uint32_t value = 0;
        while (*p >= '0' && *p <= '9') {
            uint32_t digit = (uint32_t)(*p - '0');
            if (value > (limit - digit) / 10 || digit > limit) return 0;
            value = value * 10 + digit;
            if (value > limit) return 0;
            ++p;
        }
        units[used++] = value;
        if (*p == '\0') break;
        if (*p != ',') return 0;
        ++p;
    }
    *count = used;
    return 1;
}

static int fail(const char *message)
{
    fprintf(stderr, "mwc_scan: %s\n", message);
    return 2;
}

int main(int argc, char **argv)
{
    if (argc != 6 && argc != 7) {
        return fail("usage: mwc_scan MULTIPLIER BITS UNITS_CSV BEGIN END [MAX_STORED]");
    }
    uint64_t multiplier_arg, bits_arg, begin, end, maximum_stored = 4096;
    if (!parse_decimal(argv[1], &multiplier_arg) || multiplier_arg == 0 || multiplier_arg > 65535)
        return fail("MULTIPLIER must be in 1..65535");
    if (!parse_decimal(argv[2], &bits_arg) || (bits_arg != 4 && bits_arg != 8))
        return fail("BITS must be 4 or 8");
    if (!parse_decimal(argv[4], &begin) || !parse_decimal(argv[5], &end))
        return fail("BEGIN and END must be unsigned decimal integers");
    if (argc == 7 && !parse_decimal(argv[6], &maximum_stored))
        return fail("MAX_STORED must be an unsigned decimal integer");

    const unsigned bits = (unsigned)bits_arg;
    const unsigned free_low_bits = 16 - bits;
    const uint32_t unit_mask = (UINT32_C(1) << bits) - 1;
    const uint32_t low_mask = (UINT32_C(1) << free_low_bits) - 1;
    const uint32_t multiplier = (uint32_t)multiplier_arg;
    const uint64_t domain_size = UINT64_C(1) << (32 - bits);
    if (begin > end || end > domain_size)
        return fail("interval must satisfy 0 <= BEGIN <= END <= 2^(32-BITS)");
    if (maximum_stored > domain_size || maximum_stored > SIZE_MAX / sizeof(uint32_t))
        return fail("MAX_STORED exceeds the candidate domain or allocation limit");

    uint32_t units[MAX_UNITS];
    size_t unit_count = 0;
    if (!parse_units(argv[3], unit_mask, units, &unit_count))
        return fail("UNITS_CSV must contain 1..256 nonempty decimal units in range");

    uint32_t *matches = NULL;
    if (maximum_stored != 0) {
        matches = malloc((size_t)maximum_stored * sizeof(*matches));
        if (matches == NULL) return fail("cannot allocate match storage");
    }
    uint64_t prefix_survivors[MAX_UNITS] = {0};
    prefix_survivors[0] = end - begin;
    uint64_t match_count = 0, stored_count = 0;
    struct timespec started, finished;
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        free(matches);
        return fail("cannot read monotonic clock");
    }

    for (uint64_t index = begin; index < end; ++index) {
        const uint32_t initial = (uint32_t)(((index >> free_low_bits) << 16)
                                  | ((uint64_t)units[0] << free_low_bits)
                                  | (index & low_mask));
        uint32_t state = initial;
        size_t j = 1;
        for (; j < unit_count; ++j) {
            /* multiplier <= 65535 makes this exact sum fit in uint32. */
            state = multiplier * (state & UINT32_C(65535)) + (state >> 16);
            if (((state >> free_low_bits) & unit_mask) != units[j]) break;
            ++prefix_survivors[j];
        }
        if (j == unit_count) {
            ++match_count;
            if (stored_count < maximum_stored) matches[stored_count++] = initial;
        }
    }

    if (clock_gettime(CLOCK_MONOTONIC, &finished) != 0) {
        free(matches);
        return fail("cannot read monotonic clock");
    }
    const double elapsed = (double)(finished.tv_sec - started.tv_sec)
                           + (double)(finished.tv_nsec - started.tv_nsec) / 1e9;
    printf("{\"multiplier\":%" PRIu32 ",\"bits\":%u,\"begin\":%" PRIu64
           ",\"end\":%" PRIu64 ",\"candidates_checked\":%" PRIu64
           ",\"match_count\":%" PRIu64 ",\"matches\":[",
           multiplier, bits, begin, end, end - begin, match_count);
    for (uint64_t i = 0; i < stored_count; ++i)
        printf("%s%" PRIu32, i ? "," : "", matches[i]);
    printf("],\"matches_truncated\":%s,\"elapsed_seconds\":%.9f,\"prefix_survivors\":[",
           match_count > stored_count ? "true" : "false", elapsed);
    for (size_t i = 0; i < unit_count; ++i)
        printf("%s%" PRIu64, i ? "," : "", prefix_survivors[i]);
    puts("]}");
    free(matches);
    return ferror(stdout) ? 1 : 0;
}
