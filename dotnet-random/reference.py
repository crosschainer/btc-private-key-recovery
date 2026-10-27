"""Numeric reference for the subtractive System.Random construction.

Preserves unchecked signed Int32 arithmetic, seed normalization, constructor
mixing, and the byte-output projection. Designed for synthetic fixtures."""

MODULUS = (1 << 31) - 1


def int32(value):
    """The signed result of unchecked C# int arithmetic."""
    return (value + (1 << 31)) % (1 << 32) - (1 << 31)


class LegacyRandom:
    def __init__(self, seed):
        if not isinstance(seed, int) or not -(1 << 31) <= seed < (1 << 31):
            raise ValueError("seed must be an Int32")
        subtraction = MODULUS if seed == -(1 << 31) else abs(seed)
        mj = int32(161803398 - subtraction)
        self.state = [0] * 56
        self.state[55] = mj
        mk = 1
        for i in range(1, 55):
            ii = 21 * i % 55
            self.state[ii] = mk
            mk = int32(mj - mk)
            if mk < 0:
                mk = int32(mk + MODULUS)
            mj = self.state[ii]
        for _ in range(4):
            for i in range(1, 56):
                self.state[i] = int32(self.state[i] - self.state[1 + (i + 30) % 55])
                if self.state[i] < 0:
                    self.state[i] = int32(self.state[i] + MODULUS)
        self.inext = 0
        self.inextp = 21

    @classmethod
    def from_state(cls, words, inext=0):
        """Start with any normalized 55-word state, not necessarily seeded.

        `inext=0` is the historical constructor's position; values 1..55 are
        actual ring positions. The partner retains the standard separation.
        """
        words = list(words)
        if len(words) != 55 or any(not isinstance(x, int) or not 0 <= x < MODULUS for x in words):
            raise ValueError("state requires 55 integers in [0, 2^31-1)")
        if not isinstance(inext, int) or not 0 <= inext <= 55:
            raise ValueError("inext must be in [0,55]")
        obj = cls.__new__(cls)
        obj.state = [0] + words
        obj.inext = inext
        obj.inextp = ((inext + 20) % 55) + 1
        return obj

    def next(self):
        i = self.inext + 1
        j = self.inextp + 1
        if i >= 56:
            i = 1
        if j >= 56:
            j = 1
        value = int32(self.state[i] - self.state[j])
        if value == MODULUS:
            value -= 1
        if value < 0:
            value = int32(value + MODULUS)
        self.state[i] = value
        self.inext, self.inextp = i, j
        return value

    def next_bytes(self, count):
        if not isinstance(count, int) or count < 0:
            raise ValueError("count must be a nonnegative integer")
        return bytes(self.next() & 255 for _ in range(count))
