#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include "blz.h"
#include "blz_config.h"

#define BLZ_RUN_BITS        (8 - BLZ_ML_BITS)
#define BLZ_ML_MASK         ((1U << BLZ_ML_BITS) - 1)
#define BLZ_RUN_MASK        ((1U << BLZ_RUN_BITS) - 1)
#define BLZ_WILDCOPY        8
#define BLZ_LASTLITERALS    5
#define BLZ_MFLIMIT         (BLZ_WILDCOPY + BLZ_MINMATCH)
#define BLZ_MATCH_SAFEGUARD ((2 * BLZ_WILDCOPY) - BLZ_MINMATCH)
#define BLZ_DISTANCE_MAX    65535
#define BLZ_MAX_INPUT       0x7E000000
#define BLZ_MEM_USAGE       14
#define BLZ_HASHLOG         (BLZ_MEM_USAGE - 2)
#define BLZ_HTSIZE          (1 << BLZ_MEM_USAGE)
#define BLZ_HT_U32          (1 << BLZ_HASHLOG)
#define BLZ_SKIP_TRIGGER    6
#define BLZ_ACCEL           1

#define BLZ_OV_FILL         ((uint32_t)(BLZ_OVERFLOW_BYTE)       | \
                             ((uint32_t)(BLZ_OVERFLOW_BYTE) << 8) | \
                             ((uint32_t)(BLZ_OVERFLOW_BYTE) << 16)| \
                             ((uint32_t)(BLZ_OVERFLOW_BYTE) << 24))

typedef uint8_t  BYTE;
typedef uint16_t U16;
typedef uint32_t U32;
typedef int32_t  S32;
typedef uint64_t U64;
typedef uintptr_t uptrval;

#if defined(__x86_64__) || defined(_M_X64)
typedef U64 reg_t;
#else
typedef size_t reg_t;
#endif

#define STEPSIZE sizeof(reg_t)

#ifdef __GNUC__
#  define BLZ_INLINE static inline __attribute__((always_inline))
#else
#  define BLZ_INLINE static inline
#endif

#if (defined(__GNUC__) && (__GNUC__ >= 3)) || defined(__clang__)
#  define blz_likely(x)   __builtin_expect(!!(x), 1)
#  define blz_unlikely(x) __builtin_expect(!!(x), 0)
#else
#  define blz_likely(x)   (x)
#  define blz_unlikely(x) (x)
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4)
#  define blz_memcpy(d,s,n) __builtin_memcpy(d,s,n)
#  define blz_memmove(d,s,n) __builtin_memmove(d,s,n)
#else
#  define blz_memcpy(d,s,n) memcpy(d,s,n)
#  define blz_memmove(d,s,n) memmove(d,s,n)
#endif

static unsigned blz_isLE(void) {
    const union { U32 u; BYTE c[4]; } one = { 1 };
    return one.c[0];
}

#if defined(__GNUC__) && \
    (defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || \
     defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || \
     defined(__ARM_ARCH_6ZK__) || defined(__ARM_ARCH_6T2__))
#  define BLZ_UNALIGNED 2
#elif defined(__GNUC__) || defined(__INTEL_COMPILER)
#  define BLZ_UNALIGNED 1
#else
#  define BLZ_UNALIGNED 0
#endif

#if BLZ_UNALIGNED == 2
static U16  blz_read16(const void *p)  { return *(const U16 *)p; }
static U32  blz_read32(const void *p)  { return *(const U32 *)p; }
static reg_t blz_readA(const void *p)  { return *(const reg_t *)p; }
static void blz_write16(void *p, U16 v){ *(U16 *)p = v; }
static void blz_write32(void *p, U32 v){ *(U32 *)p = v; }
#elif BLZ_UNALIGNED == 1
typedef union { U16 u16; U32 u32; reg_t uArch; } __attribute__((packed)) blz_ua;
static U16  blz_read16(const void *p)  { return ((const blz_ua *)p)->u16; }
static U32  blz_read32(const void *p)  { return ((const blz_ua *)p)->u32; }
static reg_t blz_readA(const void *p)  { return ((const blz_ua *)p)->uArch; }
static void blz_write16(void *p, U16 v){ ((blz_ua *)p)->u16 = v; }
static void blz_write32(void *p, U32 v){ ((blz_ua *)p)->u32 = v; }
#else
static U16 blz_read16(const void *p)  { U16 v; blz_memcpy(&v,p,2); return v; }
static U32 blz_read32(const void *p)  { U32 v; blz_memcpy(&v,p,4); return v; }
static reg_t blz_readA(const void *p)  { reg_t v; blz_memcpy(&v,p,sizeof(v)); return v; }
static void blz_write16(void *p, U16 v){ blz_memcpy(p,&v,2); }
static void blz_write32(void *p, U32 v){ blz_memcpy(p,&v,4); }
#endif

static U16 blz_readLE16(const void *p) {
    if (blz_isLE()) return blz_read16(p);
    const BYTE *b = (const BYTE *)p;
    return (U16)((U16)b[0] | ((U16)b[1] << 8));
}
static void blz_writeLE16(void *p, U16 v) {
    if (blz_isLE()) { blz_write16(p, v); return; }
    BYTE *b = (BYTE *)p;
    b[0] = (BYTE)v;
    b[1] = (BYTE)(v >> 8);
}

BLZ_INLINE void blz_wild8(void *dst, const void *src, void *end) {
    BYTE *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    BYTE *e = (BYTE *)end;
    do { blz_memcpy(d, s, 8); d += 8; s += 8; } while (d < e);
}

static const unsigned blz_inc32[8] = {0, 1, 2, 1, 0, 4, 4, 4};
static const int      blz_dec64[8] = {0, 0, 0,-1,-4, 1, 2, 3};

static unsigned blz_NbCommon(reg_t val) {
    if (blz_isLE()) {
        if (sizeof(val) == 8) {
#if defined(__GNUC__) && (__GNUC__ >= 4)
            return (unsigned)__builtin_ctzll((U64)val) >> 3;
#else
            const U64 m = 0x0101010101010101ULL;
            val ^= val - 1;
            return (unsigned)(((U64)((val & (m - 1)) * m)) >> 56);
#endif
        } else {
#if defined(__GNUC__) && (__GNUC__ >= 4)
            return (unsigned)__builtin_ctz((U32)val) >> 3;
#else
            const U32 m = 0x01010101;
            return (unsigned)((((val - 1) ^ val) & (m - 1)) * m) >> 24;
#endif
        }
    } else {
        if (sizeof(val) == 8) {
#if defined(__GNUC__) && (__GNUC__ >= 4)
            return (unsigned)__builtin_clzll((U64)val) >> 3;
#else
            const U64 mask = 0x0101010101010101ULL;
            U64 t = (((val >> 8) - mask) | val) & mask;
            static const unsigned char tab[128] = {
                7,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
                4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
                5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
                4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
                6,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
                4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
                5,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
                4,0,1,0,2,0,1,0,3,0,1,0,2,0,1,0,
            };
            return tab[(t * 0x0080402010080402ULL) >> 57];
#endif
        } else {
#if defined(__GNUC__) && (__GNUC__ >= 4)
            return (unsigned)__builtin_clz((U32)val) >> 3;
#else
            val >>= 8;
            val = ((((val + 0x00FFFF00) | 0x00FFFFFF) + val) |
                   (val + 0x00FF0000)) >> 24;
            return (unsigned)val ^ 3;
#endif
        }
    }
}

BLZ_INLINE unsigned blz_count(const BYTE *pIn, const BYTE *pMatch,
                              const BYTE *pInLimit) {
    const BYTE *start = pIn;
    if (blz_likely(pIn < pInLimit - (STEPSIZE - 1))) {
        reg_t d = blz_readA(pMatch) ^ blz_readA(pIn);
        if (!d) { pIn += STEPSIZE; pMatch += STEPSIZE; }
        else return blz_NbCommon(d);
    }
    while (blz_likely(pIn < pInLimit - (STEPSIZE - 1))) {
        reg_t d = blz_readA(pMatch) ^ blz_readA(pIn);
        if (!d) { pIn += STEPSIZE; pMatch += STEPSIZE; continue; }
        pIn += blz_NbCommon(d);
        return (unsigned)(pIn - start);
    }
    if ((STEPSIZE == 8) && (pIn < (pInLimit - 3)) &&
        (blz_read32(pMatch) == blz_read32(pIn)))
    { pIn += 4; pMatch += 4; }
    if ((pIn < (pInLimit - 1)) && (blz_read16(pMatch) == blz_read16(pIn)))
    { pIn += 2; pMatch += 2; }
    if ((pIn < pInLimit) && (*pMatch == *pIn)) pIn++;
    return (unsigned)(pIn - start);
}

BLZ_INLINE U32 blz_hash4(U32 seq) {
    return (seq * BLZ_HASH_PRIME32) >> (32 - BLZ_HASHLOG);
}

BLZ_INLINE U32 blz_hash5(U64 seq) {
    if (blz_isLE())
        return (U32)(((seq << 24) * BLZ_HASH_PRIME64) >> (64 - BLZ_HASHLOG));
    else
        return (U32)(((seq >> 24) * BLZ_HASH_PRIME64) >> (64 - BLZ_HASHLOG));
}

BLZ_INLINE U32 blz_hashPos(const void *p) {
    if (sizeof(reg_t) == 8) return blz_hash5(blz_readA(p));
    return blz_hash4(blz_read32(p));
}

static int blz_compress_core(const char *source, char *dest,
                             int inputSize, int maxOutputSize) {
    const BYTE *ip = (const BYTE *)source;
    const BYTE *anchor = ip;
    const BYTE *const iend = ip + inputSize;
    const BYTE *const mflimit = iend - BLZ_MFLIMIT + 1;
    const BYTE *const matchlimit = iend - BLZ_LASTLITERALS;

    BYTE *op = (BYTE *)dest;
    BYTE *const olimit = op + maxOutputSize;

    U32 ht[BLZ_HT_U32];
    memset(ht, 0, sizeof(ht));

    U32 forwardH;

    if (inputSize < (int)(BLZ_MFLIMIT + 1)) goto _last_literals;

    ht[blz_hashPos(ip)] = 0;
    ip++;
    forwardH = blz_hashPos(ip);

    for (;;) {
        const BYTE *match;
        BYTE *token;

        {
            const BYTE *forwardIp = ip;
            int step = 1;
            int searchNb = BLZ_ACCEL << BLZ_SKIP_TRIGGER;

            do {
                U32 h = forwardH;
                U32 cur = (U32)(forwardIp - (const BYTE *)source);
                U32 mi = ht[h];
                ip = forwardIp;
                forwardIp += step;
                step = (searchNb++ >> BLZ_SKIP_TRIGGER);

                if (blz_unlikely(forwardIp > mflimit)) goto _last_literals;

                forwardH = blz_hashPos(forwardIp);
                ht[h] = cur;

                match = (const BYTE *)source + mi;
                if (mi + BLZ_DISTANCE_MAX < cur) continue;
                if (blz_read32(match) == blz_read32(ip)) break;
            } while (1);
        }

        while (((ip > anchor) & (match > (const BYTE *)source)) &&
               blz_unlikely(ip[-1] == match[-1]))
        { ip--; match--; }

        {
            unsigned litLen = (unsigned)(ip - anchor);
            token = op++;

            if (blz_unlikely(op + litLen + (2 + 1 + BLZ_LASTLITERALS) +
                             (litLen / BLZ_OVERFLOW_BYTE) + 1 > olimit))
                return 0;

            if (litLen >= BLZ_RUN_MASK) {
                int rem = (int)(litLen - BLZ_RUN_MASK);
                *token = (BYTE)(BLZ_RUN_MASK << BLZ_ML_BITS);
                for (; rem >= (int)BLZ_OVERFLOW_BYTE; rem -= BLZ_OVERFLOW_BYTE)
                    *op++ = (BYTE)BLZ_OVERFLOW_BYTE;
                *op++ = (BYTE)rem;
            } else {
                *token = (BYTE)(litLen << BLZ_ML_BITS);
            }

            blz_wild8(op, anchor, op + litLen);
            op += litLen;
        }

_next_match:
        if (blz_unlikely(op + 2 + 1 + BLZ_MFLIMIT - BLZ_MINMATCH > olimit)) {
            op = token;
            goto _last_literals;
        }
        {
            U16 enc = (U16)((U32)(ip - match) ^ BLZ_OFFSET_XOR);
            blz_writeLE16(op, enc);
            op += 2;
        }

        {
            unsigned mc = blz_count(ip + BLZ_MINMATCH, match + BLZ_MINMATCH,
                                    matchlimit);
            ip += (size_t)mc + BLZ_MINMATCH;

            if (blz_unlikely(op + (1 + BLZ_LASTLITERALS) +
                             (mc / BLZ_OVERFLOW_BYTE) + 1 > olimit))
                return 0;

            if (mc >= BLZ_ML_MASK) {
                *token += (BYTE)BLZ_ML_MASK;
                mc -= BLZ_ML_MASK;
                blz_write32(op, BLZ_OV_FILL);
                while (mc >= 4 * (U32)BLZ_OVERFLOW_BYTE) {
                    op += 4;
                    blz_write32(op, BLZ_OV_FILL);
                    mc -= 4 * (U32)BLZ_OVERFLOW_BYTE;
                }
                op += mc / BLZ_OVERFLOW_BYTE;
                *op++ = (BYTE)(mc % BLZ_OVERFLOW_BYTE);
            } else {
                *token += (BYTE)mc;
            }
        }

        anchor = ip;
        if (ip >= mflimit) break;

        ht[blz_hashPos(ip - 2)] = (U32)(ip - 2 - (const BYTE *)source);

        {
            U32 h = blz_hashPos(ip);
            U32 cur = (U32)(ip - (const BYTE *)source);
            U32 mi = ht[h];
            ht[h] = cur;
            match = (const BYTE *)source + mi;

            if (mi + BLZ_DISTANCE_MAX >= cur &&
                blz_read32(match) == blz_read32(ip)) {
                token = op++;
                *token = 0;
                goto _next_match;
            }
        }

        forwardH = blz_hashPos(++ip);
    }

_last_literals:
    {
        size_t lastRun = (size_t)(iend - anchor);
        size_t ovhd = lastRun >= BLZ_RUN_MASK
            ? (lastRun - BLZ_RUN_MASK) / BLZ_OVERFLOW_BYTE + 1
            : 0;
        if (op + lastRun + 1 + ovhd > olimit)
            return 0;

        if (lastRun >= BLZ_RUN_MASK) {
            size_t acc = lastRun - BLZ_RUN_MASK;
            *op++ = (BYTE)(BLZ_RUN_MASK << BLZ_ML_BITS);
            for (; acc >= BLZ_OVERFLOW_BYTE; acc -= BLZ_OVERFLOW_BYTE)
                *op++ = (BYTE)BLZ_OVERFLOW_BYTE;
            *op++ = (BYTE)acc;
        } else {
            *op++ = (BYTE)(lastRun << BLZ_ML_BITS);
        }
        blz_memcpy(op, anchor, lastRun);
        ip = anchor + lastRun;
        op += lastRun;
    }

    return (int)(((char *)op) - dest);
}

static int blz_decompress_core(const char *src, char *dst,
                                int srcSize, int outputSize) {
    if (src == NULL || outputSize < 0) return -1;

    const BYTE *ip = (const BYTE *)src;
    const BYTE *const iend = ip + srcSize;

    BYTE *op = (BYTE *)dst;
    BYTE *const oend = op + outputSize;
    BYTE *cpy;

    unsigned token;
    size_t length, offset;
    const BYTE *match;

    if (blz_unlikely(outputSize == 0))
        return ((srcSize == 1) && (*ip == 0)) ? 0 : -1;
    if (blz_unlikely(srcSize == 0)) return -1;

    while (1) {
        if (ip >= iend) return -1;
        token = *ip++;
        length = token >> BLZ_ML_BITS;

        if (length == BLZ_RUN_MASK) {
            size_t s;
            do {
                if (blz_unlikely(ip >= iend)) return -1;
                s = *ip++;
                length += s;
                if (blz_unlikely((uptrval)(op) + length < (uptrval)(op)))
                    return -1;
            } while (s == BLZ_OVERFLOW_BYTE);
        }

        cpy = op + length;
        if ((cpy > oend - BLZ_MFLIMIT) ||
            (ip + length > iend - (2 + 1 + BLZ_LASTLITERALS))) {
            if ((ip + length != iend) || (cpy > oend))
                return -1;
            blz_memmove(op, ip, length);
            ip += length;
            op += length;
            break;
        }
        blz_wild8(op, ip, cpy);
        ip += length;
        op = cpy;

        offset = (size_t)(blz_readLE16(ip) ^ BLZ_OFFSET_XOR);
        ip += 2;
        match = op - offset;

        if (blz_unlikely(offset == 0)) return -1;
        if (blz_unlikely(match < (const BYTE *)dst)) return -1;

        length = token & BLZ_ML_MASK;
        if (length == BLZ_ML_MASK) {
            size_t s;
            do {
                if (blz_unlikely(ip >= iend - BLZ_LASTLITERALS + 1))
                    return -1;
                s = *ip++;
                length += s;
                if (blz_unlikely((uptrval)(op) + length < (uptrval)op))
                    return -1;
            } while (s == BLZ_OVERFLOW_BYTE);
        }
        length += BLZ_MINMATCH;

        cpy = op + length;

        if (blz_unlikely(cpy > oend - BLZ_LASTLITERALS)) return -1;

        if (blz_unlikely(offset < 8)) {
            blz_write32(op, 0);
            op[0] = match[0];
            op[1] = match[1];
            op[2] = match[2];
            op[3] = match[3];
            match += blz_inc32[offset];
            blz_memcpy(op + 4, match, 4);
            match -= blz_dec64[offset];
            op += 8;
            if (cpy > oend - BLZ_MATCH_SAFEGUARD) {
                BYTE *lim = oend - (BLZ_WILDCOPY - 1);
                if (op < lim) {
                    blz_wild8(op, match, lim);
                    match += lim - op;
                    op = lim;
                }
                while (op < cpy) *op++ = *match++;
            } else {
                blz_wild8(op, match, cpy);
            }
        } else {
            blz_memcpy(op, match, 8);
            match += 8;
            op += 8;
            if (blz_unlikely(cpy > oend - BLZ_MATCH_SAFEGUARD)) {
                BYTE *lim = oend - (BLZ_WILDCOPY - 1);
                if (cpy > oend - BLZ_LASTLITERALS) return -1;
                if (op < lim) {
                    blz_wild8(op, match, lim);
                    match += lim - op;
                    op = lim;
                }
                while (op < cpy) *op++ = *match++;
            } else {
                blz_memcpy(op, match, 8);
                if (length > 16) blz_wild8(op + 8, match + 8, cpy);
            }
        }
        op = cpy;
    }

    return (int)(((char *)op) - dst);
}

int blz_pack(const char *src, char *dst, int srcSize, int dstCapacity) {
    return blz_compress_core(src, dst, srcSize, dstCapacity);
}

int blz_unpack(const char *src, char *dst, int compressedSize, int dstCapacity) {
    return blz_decompress_core(src, dst, compressedSize, dstCapacity);
}

int blz_pack_bound(int isize) {
    if ((unsigned)isize > (unsigned)BLZ_MAX_INPUT) return 0;
    return isize + (isize / BLZ_OVERFLOW_BYTE) + 16;
}
