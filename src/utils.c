#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/stat.h>

#define MIN(a,b) ((a) < (b) ? (a) : (b))

/* Compatibility with C89 */
#if __STDC_VERSION__ < 199901L
#define restrict
#endif

int dnamecmp(const uint8_t *lhs, const uint8_t *rhs)
{
	/* Assume input is already checked/sanitized. */
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
	for (int i = 0; i < MIN(lp, rp); ++i) {
		const uint8_t *restrict left = lhs + ltop[i];
		const uint8_t *restrict right = rhs + rtop[i];
		const int diff = left[0] - right[0]; /* Speculative */
		int ret = memcmp(left + 1, right + 1, MIN(left[0], right[0]));
		if (ret == 0) ret = diff;
		if (ret != 0) return ret;
	}
	return lp - rp;
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
