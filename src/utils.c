#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>

#define MIN(a,b) ((a) < (b) ? (a) : (b))

/* Compatibility with C89 */
#if __STDC_VERSION__ < 199901L
#define restrict
#endif

int dnamecmp(const uint8_t *lhs, const uint8_t *rhs)
{
	/* Assume input is already checked/sanitized. */
	int i = 0;
	uint8_t lstack[128], rstack[128];
	uint8_t *restrict ltop = lstack + sizeof(lstack);
	uint8_t *restrict rtop = rstack + sizeof(rstack);
	int lp = 0, rp = 0; /* Make sure it can use 32bit RIP-relative addressing */
	while (1) {
		const uint8_t left = lhs[lp], right = rhs[rp];
		if (left > 0) {
			*--ltop = lp;
			lp += left + 1;
		} /* Unrolled both labels in loop pass for improved ILP. */
		if(right > 0) {
			*--rtop = rp;
			rp += right + 1;
		}
		if (left + right == 0)
			break;
	}
	/* Compare reordered labels from last to first */
	lp = lstack + sizeof(lstack) - ltop; /* Reuse to avoid register spill */
	rp = rstack + sizeof(rstack) - rtop;
	for (i = 0; i < MIN(lp, rp); ++i) {
		const uint8_t *restrict left = lhs + ltop[i];
		const uint8_t *restrict right = rhs + rtop[i];
		const int diff = left[0] - right[0]; /* Speculative */
		int ret = memcmp(left + 1, right + 1, MIN(left[0], right[0]));
		if (ret == 0) ret = diff;
		if (ret != 0) return ret;
	}
	return lp - rp;
}

int dnamekey(uint8_t *restrict dst, const uint8_t *restrict src)
{
	if (!dst || !src) {
		return 0;
	}
	/* Count length to last label */
	size_t len = 0;
	while (src[len] > 0) {
		len += src[len] + 1;
	}
	/* Write labels from back to get reversed order */
	size_t r = 0;
	while (src[r] > 0) { /* Until empty label */
		const uint8_t rlen = src[r] + 1;
		dst[len - 1] = 0x00; /* Zero label length */
		len -= rlen; /* Base for label start */
		memcpy(dst + len, src + r + 1, rlen - 1);
		r += rlen;
	}
	return r;
}

/* Fetch file last modified time. */
unsigned mtime(const char *path)
{
	struct stat s;
	if (stat(path, &s) == 0) {
		return s.st_mtime;
	}
	return 0;
}

/* Return time bracket.
 * @note moved to C because it's unpredictably branchy.
 */
unsigned bucket(unsigned l)
{
	if      (l <= 1)    return 1;
	else if (l <= 10)   return 10;
	else if (l <= 50)   return 50;
	else if (l <= 100)  return 100;
	else if (l <= 250)  return 250;
	else if (l <= 500)  return 500;
	else if (l <= 1000) return 1000;
	else if (l <= 1500) return 1500;
	return 3000;
}
