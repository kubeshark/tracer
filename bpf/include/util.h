/*
SPDX-License-Identifier: GPL-3.0
Copyright (C) Kubeshark
*/

#ifndef __UTIL__
#define __UTIL__

#define MIN(a,b) (((a)<(b))?(a):(b))

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#endif /* __UTIL__ */
