/* Independent numeric oracle for the original Marsaglia xorshift128.
 * The caller supplies four uint32 words, ordered x, y, z, w.  Each output
 * is the updated w; the input state is not emitted as an output word.
 * No Python experiment code or generated constants are included here.
 */
#include <stddef.h>
#include <stdint.h>

void xs128_stream(uint32_t x, uint32_t y, uint32_t z, uint32_t w,
                  uint32_t *output, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        const uint32_t t = x ^ (x << 11);
        x = y;
        y = z;
        z = w;
        w = (w ^ (w >> 19)) ^ (t ^ (t >> 8));
        output[i] = w;
    }
}
