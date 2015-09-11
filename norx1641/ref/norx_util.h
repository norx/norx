/*
   NORX reference source code package - reference C implementations

   Written 2014-2015 by:

        - Samuel Neves <sneves@dei.uc.pt>
        - Philipp Jovanovic <jovanovic@fim.uni-passau.de>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along with
   this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#ifndef NORX_DEFS_H
#define NORX_DEFS_H

/* Workaround for C89 compilers */
#if !defined(__cplusplus) && (!defined(__STDC_VERSION__) || __STDC_VERSION__ < 199901L)
  #if   defined(_MSC_VER)
    #define NORX_INLINE __inline
  #elif defined(__GNUC__)
    #define NORX_INLINE __inline__
  #else
    #define NORX_INLINE
  #endif
#else
  #define NORX_INLINE inline
#endif

#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>

#define BITS(x) (sizeof(x) * CHAR_BIT)
#define BYTES(x) (((x) + 7) / 8)
#define WORDS(x) (((x) + (NORX_W-1)) / NORX_W)

#define ROTL(x, c) ( ((x) << (c)) | ((x) >> (BITS(x) - (c))) )
#define ROTR(x, c) ( ((x) >> (c)) | ((x) << (BITS(x) - (c))) )


static NORX_INLINE uint8_t load8(const void * in)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint8_t v;
    memcpy(&v, in, sizeof v);
    return v;
#else
    const uint8_t * p = (const uint8_t *)in;
    return ((uint8_t)p[0] << 0);
#endif
}


static NORX_INLINE uint16_t load16(const void * in)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    uint16_t v;
    memcpy(&v, in, sizeof v);
    return v;
#else
    const uint8_t * p = (const uint8_t *)in;
    return ((uint16_t)p[0] << 0) |
           ((uint16_t)p[1] << 8);
#endif
}


static NORX_INLINE void store8(void * out, const uint8_t v)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    memcpy(out, &v, sizeof v);
#else
  uint8_t * p = (uint8_t *)out;
  p[0] = (uint8_t)(v >> 0);
#endif
}


static NORX_INLINE void store16(void * out, const uint16_t v)
{
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
    memcpy(out, &v, sizeof v);
#else
  uint8_t * p = (uint8_t *)out;
  p[0] = (uint8_t)(v >> 0);
  p[1] = (uint8_t)(v >> 8);
#endif
}


static void* (* const volatile burn)(void*, int, size_t) = memset;

#endif

