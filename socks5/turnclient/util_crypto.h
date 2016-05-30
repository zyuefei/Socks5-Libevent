/**
 * \file util_crypto.h
 * \author hong.he
 * \date 2012-2013
 */

#ifndef UTIL_CRYPTO_H
#define UTIL_CRYPTO_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef _MSC_VER
/* Microsoft compiler does not have stdint.h */
#include <stdint.h>
#else
/* replacement for stdint.h */
typedef __int8 int8_t;
typedef unsigned __int8 uint8_t;
typedef __int16 int16_t;
typedef unsigned __int16 uint16_t;
typedef __int32 int32_t;
typedef unsigned __int32 uint32_t;
typedef __int64 int64_t;
typedef unsigned __int64 uint64_t;
#endif

#endif /* UTIL_CRYPTO_H */

