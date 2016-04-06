/*
 * af_ktls tool
 *
 * Copyright (C) 2016 Fridolin Pokorny <fpokorny@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#define _DEFAULT_SOURCE // for htobe64()

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <limits.h>
#include <string.h>
#include <endian.h>

#define SEQ_NUM_SIZE		8

struct tls_sock {
	struct {
		uint64_t bits;
		unsigned start;
	} dtls_window;
	char iv_recv[SEQ_NUM_SIZE];
};

static struct tls_sock tsk;

static void print_bits(uint64_t b) {
	for (int i = 0; i < sizeof(b) * CHAR_BIT; i++) {
		fprintf(stderr, "%lu", (b >> i) & 1);
	}
	putc('\n', stderr);
}

#define be64_to_cpu			htobe64

/******************************** from af_ktls.c *******************/
/*
 * DTLS sliding window handling
 */
#define DTLS_EPOCH_SHIFT		(6*CHAR_BIT)
#define DTLS_SEQ_NUM_MASK		0x0000FFFFFFFFFFFF

#define DTLS_WINDOW_INIT(W)		((W).bits = (W.start) = 0)

#define DTLS_SAME_EPOCH(S1, S2)		(((S1) >> DTLS_EPOCH_SHIFT) == ((S2) >> DTLS_EPOCH_SHIFT))

#define DTLS_WINDOW_INSIDE(W, S)	((((S) & DTLS_SEQ_NUM_MASK) > (W).start) && \
						(((S)  & DTLS_SEQ_NUM_MASK) - (W).start <= (sizeof((W).bits) * CHAR_BIT)))

#define DTLS_WINDOW_OFFSET(W, S)	((((S) & DTLS_SEQ_NUM_MASK) - (W).start) - 1)

#define DTLS_WINDOW_RECEIVED(W, S)	(((W).bits & ((uint64_t) 1 << DTLS_WINDOW_OFFSET(W, S))) != 0)

#define DTLS_WINDOW_MARK(W, S)		((W).bits |= ((uint64_t) 1 << DTLS_WINDOW_OFFSET(W, S)))

#define DTLS_WINDOW_UPDATE(W)		while ((W).bits & (uint64_t) 1) { \
						(W).bits = (W).bits >> 1; \
						(W).start++; \
					}

/*
 * Handle DTLS sliding window
 * rv: rv < 0  drop packet
 *     rv == 0 OK
 */
static inline int dtls_window(struct tls_sock *tsk, const char * sn)
{
	uint64_t *seq_num_ptr, *seq_num_last_ptr;
	uint64_t seq_num, seq_num_last;

	seq_num_ptr = (uint64_t *) sn;
	seq_num_last_ptr = (uint64_t *) tsk->iv_recv;
	
	seq_num = be64_to_cpu(*seq_num_ptr);
	seq_num_last = be64_to_cpu(*seq_num_last_ptr);

	if (!DTLS_SAME_EPOCH(seq_num_last, seq_num))
		return -1;

	/* are we inside sliding window? */
	if (!DTLS_WINDOW_INSIDE(tsk->dtls_window, seq_num))
		return -2;

	/* already received? */
	if (DTLS_WINDOW_RECEIVED(tsk->dtls_window, seq_num))
		return -3;

	DTLS_WINDOW_MARK(tsk->dtls_window, seq_num);
	DTLS_WINDOW_UPDATE(tsk->dtls_window);

	return 0;
}

/**************************** end from af_ktls.c *******************/

static void do_print(int err, const char *n, const char *sn) {
	fprintf(stderr, "err = %d, start: %u\nwindow:\n", err, tsk.dtls_window.start);
	print_bits(tsk.dtls_window.bits);
	putc('\n', stderr);
}

#define TEST(N) do { \
		fprintf(stderr, "--> test: %d\n", ++i); \
		err = dtls_window(&tsk, N); \
		do_print(err, N, tsk.iv_recv); \
	} while(0);

static char *seq_num(uint64_t epoch, uint64_t sn) {
	static char sequence_number[SEQ_NUM_SIZE];

	sn = (epoch << DTLS_EPOCH_SHIFT) | (sn & DTLS_SEQ_NUM_MASK);
	sn = htobe64(sn);
	memcpy(sequence_number, &sn, SEQ_NUM_SIZE);

	return sequence_number;
}

int main(void) {
	int err;
	int i = 0;

	tsk.dtls_window.bits = 0;
	tsk.dtls_window.start = 0;
	memcpy(tsk.iv_recv, seq_num(0, 1), SEQ_NUM_SIZE);

	TEST(seq_num(0, 64));   // 1
	TEST(seq_num(0, 1));    // 2
	TEST(seq_num(0, 2));    // 3
	TEST(seq_num(0, 2));    // 4
	TEST(seq_num(0, 6));    // 5
	TEST(seq_num(0, 10));   // 6
	TEST(seq_num(0, 11));   // 7
	TEST(seq_num(0, 12));   // 8
	TEST(seq_num(0, 65));   // 9
	TEST(seq_num(0, 10));   // 10
	TEST(seq_num(0, 2));    // 11
	TEST(seq_num(0, 64));   // 12
	TEST(seq_num(1, 64));   // 13

	return 0;
}

