#include "unity.h"
#include "stdio.h"
#include "stdlib.h"
#include "nvblk/nvblk.h"

#ifndef UNITY_INCLUDE_PRINT_FORMATTED
#define TEST_PRINTF(cmd)
#endif

#define LOG2_BS 8	/* BS (block size) = 256 */
#define LOG2_BPEB 3	/* LOG2_BS = 7 requires LOG2_BPEB >= 2 */
                        /* LOG2_BS = 8 requires LOG2_BPEB >= 3 */
			/* LOG2_BS = 9 requires LOG2_BPEB >= 3 */
#define EB 5            /* 5 erase blocks */
#define SPEB 1          /* 1 spare erase block */
#define BBSPEB 3	/* 3 spare erase blocks in for 2 bad blocks case */

uint8_t data[EB << (LOG2_BS + LOG2_BPEB)] = { 0xff };

static int my_read(const struct nvb_config *cfg, uint32_t p, void *buffer)
{
	const uint32_t bsize = (1 << cfg->log2_bs);
	const uint32_t off = p * bsize;
	uint8_t *buf = (uint8_t *)buffer;

	if (off >= sizeof(data)) {
		return -NVB_EINVAL;
	}

	memcpy(buf, &data[off], bsize);
	return 0;
}

static int my_prog(const struct nvb_config *cfg, uint32_t p, const void *buffer)
{
	const uint32_t bsize = (1 << cfg->log2_bs);
	const uint32_t ebsize = (1 << (cfg->log2_bs + cfg->log2_bpeb));
	const uint32_t off = p * bsize;
	const uint8_t *buf = (const uint8_t *)buffer;

	if (off >= sizeof(data)) {
		return -NVB_EINVAL;
	}

	if (off % ebsize == 0U) {
		memset(&data[off], 0xff, ebsize);
	}

	memcpy(&data[off], buf, bsize);
	return 0;
}

uint8_t mbuf[(1 << LOG2_BS)];
uint8_t gbuf[(1 << LOG2_BS)];

struct nvb_config allgoodcfg = {
	.mb = mbuf,
	.gb = gbuf,
#ifdef NVB_CFG_INITDEINIT
	.init = NULL,
	.deinit = NULL,
#endif /* NVB_CFG_INITDEINIT */
	.read = my_read,
	.prog = my_prog,
#ifdef NVB_CFG_THREADSAFE
	.lock = NULL,
	.unlock = NULL,
#endif /* NVB_CFG_THREADSAFE */
	.log2_bs = LOG2_BS,
	.log2_bpeb = LOG2_BPEB,
	.eb = EB,
	.sp_eb = SPEB,
};

static uint32_t bad_block0;
static uint32_t bad_block1;

static int my_prog_bad(const struct nvb_config *cfg, uint32_t p, const void *buffer)
{
	const uint32_t bsize = (1 << cfg->log2_bs);
	const uint32_t ebsize = (1 << (cfg->log2_bs + cfg->log2_bpeb));
	const uint32_t off = p * bsize;
	const uint8_t *buf = (const uint8_t *)buffer;

	if (off >= sizeof(data)) {
		return -NVB_EINVAL;
	}

	if (off % ebsize == 0U) {
		memset(&data[off], 0xff, ebsize);
	}

	if ((p == bad_block0) || (p == bad_block1)) {
		return -NVB_EFAULT;
	}

	memcpy(&data[off], buf, bsize);
	return 0;
}

struct nvb_config badblockcfg = {
	.mb = mbuf,
	.gb = gbuf,
#ifdef NVB_CFG_INITDEINIT
	.init = NULL,
	.deinit = NULL,
#endif /* NVB_CFG_INITDEINIT */
	.read = my_read,
	.prog = my_prog_bad,
#ifdef NVB_CFG_THREADSAFE
	.lock = NULL,
	.unlock = NULL,
#endif /* NVB_CFG_THREADSAFE */
	.log2_bs = LOG2_BS,
	.log2_bpeb = LOG2_BPEB,
	.eb = EB,
	.sp_eb = BBSPEB,
};

struct nvb_info test;

static void small_report_nvb(struct nvb_info *info)
{
	printf("Head at mblock [%d], Tail at mblock [%d]\n", info->head,
	       info->tail);
	printf("Root at mblock [%d]\n", info->root);
	printf("cpe [%d], tail_cpe [%d]\n", info->cpe, info->tail_cpe);
	printf("used [%d], pass [%x]\n", info->used, info->pass);
}

static void report_nvb(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	uint32_t bcnt;

	nvb_ioctl(info, NVB_CMD_GET_BLK_COUNT, (void *)&bcnt);

	printf("-------------------------------------\n");
	printf("Non volatile block area\n");
	printf("-------------------------------------\n");
	printf("Block size: %d, Blocks: %d, blocks per checkpoint: %d\n",
	            (1 << cfg->log2_bs), bcnt, (1 << info->log2_bpcp) - 1);
	small_report_nvb(info);
	printf("-------------------------------------\n");
}

static void clear_nvb_storage(void)
{
	memset(data, 0xff, sizeof(data));
}

static void init_nvb(struct nvb_info *info, const struct nvb_config *cfg)
{
	uint32_t bcnt;
	int rc;

	info->cfg = NULL;
	clear_nvb_storage();

	rc = nvb_init(info, cfg);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "init failed");
	TEST_ASSERT_EQUAL_HEX16_MESSAGE(NVB_BLOCK_NONE, info->root, "bad root");
	TEST_ASSERT_EQUAL_UINT16_MESSAGE(0, info->head, "bad head");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, info->cpe, "bad cpe");
	TEST_ASSERT_EQUAL_UINT16_MESSAGE(0, info->tail, "bad tail");
	TEST_ASSERT_EQUAL_UINT8_MESSAGE(0, info->tail_cpe, "bad tail cpe");
	TEST_ASSERT_EQUAL_UINT16_MESSAGE(0, info->used, "bad used");
	rc = nvb_ioctl(info, NVB_CMD_GET_BLK_COUNT, (void *)&bcnt);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "ioctl failed");

	rc = nvb_init(info, cfg);
	TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(0, rc, "reinit should fail");
}

static void test_set_block(char *buf, char value, uint32_t size)
{
	memset(buf, value, size);
}

void setUp(void)
{
}

void tearDown(void)
{
}

void test_rwd(struct nvb_config *cfg, uint16_t *sector, uint8_t *sector_val)
{
	struct nvb_info *tst = &test;
	const uint32_t bs = (1 << cfg->log2_bs);
	char wr_data[bs], rd_data[bs];
	uint32_t bcnt;
	int rc;

	/* Acquire tst */
	init_nvb(tst, cfg);

	/* Get the maximum allowed blocks */
	nvb_ioctl(tst, NVB_CMD_GET_BLK_COUNT, (void *)&bcnt);

	/* Write data */
	for (size_t i = 0; i < bcnt; i++) {
		test_set_block(wr_data, sector_val[i], bs);
		rc = nvb_write(tst, wr_data, sector[i], 1);
		TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "write failed");
	}

	for (size_t i = bcnt >> 1; i < bcnt; i++) {
		test_set_block(wr_data, sector_val[i], bs);
		rc = nvb_write(tst, wr_data, sector[i], 1);
		TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "write failed");
	}

	rc = nvb_sync(tst);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "sync failed");

	/* Read data */
	for (size_t i = 0; i < bcnt; i++) {
		test_set_block(wr_data, sector_val[i], bs);
		rc = nvb_read(tst, rd_data, sector[i], 1);
		TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "read failed");
		TEST_ASSERT_EQUAL_MEMORY_MESSAGE(wr_data, rd_data, bs, "data error");
	}

	/* Release tst */
	rc = nvb_deinit(tst);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "deinit failed");
	/* Acquire tst */
	rc = nvb_init(tst, cfg);
	TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "init failed");

	/* Read */
	for (size_t i = 0; i < bcnt; i++) {
		test_set_block(wr_data, sector_val[i], bs);
		rc = nvb_read(tst, rd_data, sector[i], 1);
		TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "read failed");
		TEST_ASSERT_EQUAL_MEMORY_MESSAGE(wr_data, rd_data, bs, "data error");
	}

	/* Delete */
	for (size_t i = 0; i < bcnt; i++) {
		rc = nvb_delete(tst, sector[i], 1);
		TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "delete failed");
		rc = nvb_sync(tst);
		TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "sync failed");
		for (size_t j = 0; j <= i; j++) {
			rc = nvb_read(tst, rd_data, sector[i], 1);
			TEST_ASSERT_NOT_EQUAL_INT_MESSAGE(0, rc, "read succeeded");
		}
		for (size_t j = i + 1; j < bcnt; j++) {
			test_set_block(wr_data, sector_val[j], bs);
			rc = nvb_read(tst, rd_data, sector[j], 1);
			TEST_ASSERT_EQUAL_INT_MESSAGE(0, rc, "read failed");
			TEST_ASSERT_EQUAL_MEMORY_MESSAGE(wr_data, rd_data, bs, "data error");
		}
	}
}

void test_init_good(void)
{
	struct nvb_config *cfg = &allgoodcfg;
	struct nvb_info *tst = &test;

	init_nvb(tst, cfg);
	report_nvb(tst);
}

void test_init_bad(void)
{
	struct nvb_config *cfg = &badblockcfg;
	struct nvb_info *tst = &test;

	init_nvb(tst, cfg);
	report_nvb(tst);
}

void test_rwd_lin_good(void) {
	uint16_t sector[((1 << LOG2_BPEB) * EB)];
	uint8_t sector_val[((1 << LOG2_BPEB) * EB)];

	for (size_t i = 0; i < ((1 << LOG2_BPEB) * EB); i++) {
		sector[i] = (uint16_t)i;
		sector_val[i] = (uint8_t)i;
	}

	test_rwd(&allgoodcfg, sector, sector_val);
}

void test_rwd_lin_bad(void) {
	uint16_t sector[((1 << LOG2_BPEB) * EB)];
	uint8_t sector_val[((1 << LOG2_BPEB) * EB)];

	for (size_t i = 0; i < ((1 << LOG2_BPEB) * EB); i++) {
		sector[i] = (uint16_t)i;
		sector_val[i] = (uint8_t)i;
	}

	for (int i = 0; i < ((1 << LOG2_BPEB) * EB); i++) {
	 	bad_block0 = rand() % ((1 << LOG2_BPEB) * EB);
		bad_block1 = rand() % ((1 << LOG2_BPEB) * EB);
		test_rwd(&badblockcfg, sector, sector_val);
	}
}

void test_rwd_rnd_good(void) {
	uint16_t sector[((1 << LOG2_BPEB) * EB)];
	uint8_t sector_val[((1 << LOG2_BPEB) * EB)];

	for (size_t i = 0; i < ((1 << LOG2_BPEB) * EB); i++) {
		sector[i] = (uint16_t)rand();
		sector_val[i] = (uint8_t)i;
	}

	test_rwd(&allgoodcfg, sector, sector_val);
}

void test_rwd_rnd_bad(void) {
	uint16_t sector[((1 << LOG2_BPEB) * EB)];
	uint8_t sector_val[((1 << LOG2_BPEB) * EB)];

	for (size_t i = 0; i < ((1 << LOG2_BPEB) * EB); i++) {
		sector[i] = (uint16_t)rand();
		sector_val[i] = (uint8_t)i;
	}

	for (int i = 0; i < ((1 << LOG2_BPEB) * EB); i++) {
		bad_block0 = rand() % ((1 << LOG2_BPEB) * EB);
		bad_block1 = rand() % ((1 << LOG2_BPEB) * EB);
		test_rwd(&badblockcfg, sector, sector_val);
	}
}

int main(void)
{
	UNITY_BEGIN();
	RUN_TEST(test_init_good);
	RUN_TEST(test_init_bad);
	RUN_TEST(test_rwd_lin_good);
	RUN_TEST(test_rwd_lin_bad);
	RUN_TEST(test_rwd_rnd_good);
	RUN_TEST(test_rwd_rnd_bad);
	return UNITY_END();
}