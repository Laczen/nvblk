/*
 * Copyright (c) 2021 Laczen
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "nvblk/nvblk.h"

/* Lock and unlock for thread safety */
static inline int cfg_lock(const struct nvb_config *cfg)
{
#ifdef NVB_CFG_THREADSAFE
	if (cfg->lock == NULL) {
		return 0;
	}

	return cfg->lock(cfg);
#else
	(void)cfg;
	return 0;
#endif
}

static inline int cfg_unlock(const struct nvb_config *cfg)
{
#ifdef NVB_CFG_THREADSAFE
	if (cfg->unlock == NULL) {
		return 0;
	}

	return cfg->unlock(cfg);
#else
	(void)cfg;
	return 0;
#endif
}

/* Hardware init and deinit routines */
static inline int cfg_init(const struct nvb_config *cfg)
{
#ifdef NVB_CFG_INITDEINIT
	if (cfg->init == NULL) {
		return 0;
	}

	return cfg->init(cfg);
#else
	(void)cfg;
	return 0;
#endif
}

static int cfg_deinit(const struct nvb_config *cfg)
{
#ifdef NVB_CFG_INITDEINIT
	if (cfg->deinit == NULL) {
		return 0;
	}

	return cfg->deinit(cfg);
#else
	(void)cfg;
	return 0;
#endif
}

/* Physical blocks interface */
/* Read from physical block */
static int pb_read(const struct nvb_config *cfg, uint8_t *buf, uint32_t p)
{
	return cfg->read(cfg, p, (void *)buf);
}

/* Write to physical block */
static int pb_write(const struct nvb_config *cfg, const uint8_t *buf,
		    uint32_t p)
{
	return cfg->prog(cfg, p, (const void *)buf);
}

/* Meta general routines */
static uint32_t nvb_get32(const uint8_t *buf)
{
	return ((uint32_t)buf[0] | (((uint32_t)buf[1]) << 8) |
	        (((uint32_t)buf[2]) << 16) | (((uint32_t)buf[3]) << 24));
}

static inline void nvb_set32(uint8_t *buf, uint32_t val)
{
	buf[0] = (uint8_t)val;
	buf[1] = (uint8_t)(val >> 8);
	buf[2] = (uint8_t)(val >> 16);
	buf[3] = (uint8_t)(val >> 24);
}

static uint16_t nvb_get16(const uint8_t *buf)
{
	return ((uint16_t)buf[0] | (((uint16_t)buf[1]) << 8));
}

static inline void nvb_set16(uint8_t *buf, uint16_t val)
{
	buf[0] = (uint8_t)val;
	buf[1] = (uint8_t)(val >> 8);
}

/* Meta set magic */
static void meta_set_magic(uint8_t *meta)
{
	const size_t off = NVB_CP_MAGIC_START;

	memcpy(meta + off, NVB_CP_MAGIC, sizeof(NVB_CP_MAGIC) - 1);
}

/* Meta verify magic */
static bool meta_vrf_magic(const uint8_t *meta)
{
	const size_t off = NVB_CP_MAGIC_START;

	if (memcmp(meta + off, NVB_CP_MAGIC, sizeof(NVB_CP_MAGIC) - 1) != 0) {
		return false;
	}

	return true;
}

/* Meta set version */
static void meta_set_version(uint8_t *meta, uint32_t version)
{
	const size_t off = NVB_CP_VERSION_START;

	nvb_set32(meta + off, version);
}

/* Meta set tail */
static void meta_set_tail(uint8_t *meta, uint16_t tail)
{
	const size_t off = NVB_CP_TAIL_START;

	nvb_set16(meta + off, tail);
}

/* Meta get tail */
static uint16_t meta_get_tail(uint8_t *meta)
{
	const size_t off = NVB_CP_TAIL_START;

	return nvb_get16(meta + off);
}

/* Meta set tail cpe */
static void meta_set_tail_cpe(uint8_t *meta, uint8_t cpe)
{
	const size_t off = NVB_CP_TAIL_ENTRY_START;

	meta[off] = cpe;
}

/* Meta get tail cpe */
static uint8_t meta_get_tail_cpe(uint8_t *meta)
{
	const size_t off = NVB_CP_TAIL_ENTRY_START;

	return meta[off];
}

/* Meta get pass */
static uint8_t meta_get_pass(const uint8_t *meta)
{
	const size_t off = NVB_CP_PASS_START;

	return meta[off];
}

/* Meta set pass */
static void meta_set_pass(uint8_t *meta, uint8_t pass)
{
	const size_t off = NVB_CP_PASS_START;

	meta[off] = pass;
}

/* Meta verify pass */
static bool meta_vrf_pass(uint8_t *meta)
{
	const size_t off = NVB_CP_PASS_START;

	if ((meta[off] != NVB_CP_PASS_EVEN) &&
	    (meta[off] != NVB_CP_PASS_ODD)) {
		return false;
	}

	return true;
}

/* Meta set used */
static void meta_set_used(uint8_t *meta, uint16_t used)
{
	const size_t off = NVB_CP_USED_START;

	nvb_set16(meta + off, used);
}

/* Meta get used */
static uint16_t meta_get_used(uint8_t *meta)
{
	const size_t off = NVB_CP_USED_START;

	return nvb_get16(meta + off);
}

/* Meta retrieve map entry */
static uint8_t *meta_me(uint8_t *meta, uint8_t entry)
{
	return meta + NVB_CP_MAP_START + entry * NVB_CP_MAP_ENTRY_SIZE;
}

/* Meta set map entry target */
static void meta_me_set_target(uint8_t *meta_me, uint16_t target)
{
	nvb_set16(meta_me, target);
}

/* Meta get map entry target */
static uint16_t meta_me_get_target(const uint8_t *meta_me)
{
	return nvb_get16(meta_me);
}

/* Meta set map entry alt pointer at depth */
static void meta_me_set_alt(uint8_t *meta_me, uint16_t alt, uint8_t d)
{
	const size_t off = NVB_CP_MAP_TARGET_SIZE + d * NVB_CP_MAP_ALT_SIZE;

	nvb_set16(meta_me + off, alt);
}

/* Meta get map entry alt pointer at depth */
static uint16_t meta_me_get_alt(const uint8_t *meta_me, uint8_t d)
{
	const size_t off = NVB_CP_MAP_TARGET_SIZE + d * NVB_CP_MAP_ALT_SIZE;

	return nvb_get16(meta_me + off);
}

/* Software CRC implementation with small lookup table */
static uint32_t crc32(uint32_t crc, const void *buffer, size_t size) {
	const uint8_t *data = buffer;
	static const uint32_t rtable[16] = {
		0x00000000, 0x1db71064, 0x3b6e20c8, 0x26d930ac,
		0x76dc4190, 0x6b6b51f4, 0x4db26158, 0x5005713c,
		0xedb88320, 0xf00f9344, 0xd6d6a3e8, 0xcb61b38c,
		0x9b64c2b0, 0x86d3d2d4, 0xa00ae278, 0xbdbdf21c,
	};

	for (size_t i = 0; i < size; i++) {
		crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 0)) & 0xf];
		crc = (crc >> 4) ^ rtable[(crc ^ (data[i] >> 4)) & 0xf];
	}

	return crc;
}

/* Meta get crc */
static uint32_t meta_get_crc(const uint8_t *meta, size_t bs)
{
	return nvb_get32(meta + bs - NVB_CP_CRC_SIZE);
}

/* Meta calculate crc */
static uint32_t meta_clc_crc(const uint8_t *meta, size_t bs)
{
	return crc32(NVB_CP_CRC_INIT, meta, bs - NVB_CP_CRC_SIZE);
}

/* Meta set crc */
static void meta_set_crc(uint8_t *meta, size_t bs)
{
	uint32_t crc32val = meta_clc_crc(meta, bs);

	nvb_set32(meta + bs - NVB_CP_CRC_SIZE, crc32val);
}

/* Meta verify crc */
static bool meta_vrf_crc(const uint8_t *meta, size_t bs)
{
	if (meta_get_crc(meta, bs) != meta_clc_crc(meta, bs)) {
		return false;
	}

	return true;
}

/* Meta verify validity: correct pass, magic and crc */
static bool nvb_meta_valid(struct nvb_info *info, uint8_t *meta)
{
	const size_t bs = (1 << info->cfg->log2_bs);

	if ((!meta_vrf_pass(meta)) || (!meta_vrf_magic(meta)) ||
	    (!meta_vrf_crc(meta, bs))) {
		return false;
	}

	return true;
}

/* Return a uint16_t with bit set at depth */
static inline uint16_t d_bit(int depth)
{
	return ((uint16_t)1) << (NVB_CP_MAP_ALT_CNT - depth - 1);
}

/* Retrieve meta page and (optional) cpe */
static uint8_t *nvb_get_meta(struct nvb_info *info, uint16_t mpage, uint8_t *cpe)
{
	const struct nvb_config *cfg = info->cfg;
	const uint32_t p = mpage << info->log2_bpcp;
	const uint8_t bpcp = (1 << info->log2_bpcp) - 1;

	if (mpage == NVB_BLOCK_NONE) {
		return NULL;
	}

	if (mpage == info->head) {
		if (cpe != NULL) {
			*cpe = info->cpe;
		}

		return cfg->mb;
	}

	if ((pb_read(info->cfg, cfg->gb, p + bpcp) != 0) ||
	    (!nvb_meta_valid(info, cfg->gb)))  {
		return NULL;
	}

	if (cpe != NULL) {
		*cpe = bpcp;
	}

	return cfg->gb;
}

/* Trace a target and construct new meta map entry (meta_me).
 * Returns 0 if found, -NVB_ENOENT if not found.
 */
static int nvb_meta_trace(struct nvb_info *info, uint16_t target, uint32_t *p,
			  uint8_t *new_meta_me)
{
	uint16_t tr_meta, tr_target = 0;
	uint16_t mask = 0U;
	uint8_t *meta, *tr_meta_me = NULL, cpe;
	bool cpe_sb = true;
	uint8_t d = 0;

	/* Search the metapage of the block of target, update *new_meta_me
	 * while searching.
	 */

	meta_me_set_target(new_meta_me, target);
	tr_meta = info->root;
	meta = nvb_get_meta(info, tr_meta, &cpe);
	if (meta == NULL) {
		goto not_found;
	}

	while (true) {
		while (cpe_sb) {
			cpe--;
			tr_meta_me = meta_me(meta, cpe);
			tr_target = meta_me_get_target(tr_meta_me);
			if ((target & mask) == (tr_target & mask)) {
				cpe_sb = false;
			}
		}

		if (d == NVB_CP_MAP_ALT_CNT) {
			break;
		}

		mask >>= 1;
		mask |= 0x8000;

		if ((target & mask) != (tr_target & mask)) {
			/* No match at depth d, follow alt pointer */

			uint16_t tr_meta_prev = tr_meta;

			meta_me_set_alt(new_meta_me, tr_meta, d);
			tr_meta = meta_me_get_alt(tr_meta_me, d);

			if (tr_meta != tr_meta_prev) {
				meta = nvb_get_meta(info, tr_meta, &cpe);
				if (meta == NULL) {
					d++;
					goto not_found;
				}
			}

			cpe_sb = true;
		} else {
			/* Match at depth d, update alt pointer */
			meta_me_set_alt(new_meta_me,
					meta_me_get_alt(tr_meta_me, d),
						d);
		}

		d++;
	}

	/* Reduce cpe until target is reached */
	while (target != meta_me_get_target(tr_meta_me)) {
		cpe--;
		tr_meta_me = meta_me(meta, cpe);
	}

	*p = (tr_meta << info->log2_bpcp) + cpe;
	return 0;

not_found:
	while (d < NVB_CP_MAP_ALT_CNT) {
		meta_me_set_alt(new_meta_me, NVB_BLOCK_NONE, d);
		d++;
	}

	return -NVB_ENOENT;
}

/* Advance a metapage counter and wrap around */
static void nvb_advance(struct nvb_info *info, uint16_t *page)
{
	const struct nvb_config *cfg = info->cfg;
	const uint32_t cp_cnt = cfg->eb << (cfg->log2_bpeb - info->log2_bpcp);

	(*page)++;
	if (*page == cp_cnt) {
		*page = 0U;
	}
}

/* Advance the head of the logical block solution */
static void nvb_head_advance(struct nvb_info *info)
{
	nvb_advance(info, &info->head);
	if (info->head == 0U) {
		info->pass = ~info->pass;
	}

	info->cpe = 0U;
}

/* Write the current metapage */
static int nvb_add_meta(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	const size_t bs = (1 << cfg->log2_bs);
	const uint32_t p = info->head << info->log2_bpcp;
	uint8_t *meta = cfg->mb;
	int rc;

	meta_set_magic(meta);
	meta_set_version(meta, NVB_VERSION);
	meta_set_tail(meta, info->tail);
	meta_set_tail_cpe(meta, info->tail_cpe);
	meta_set_pass(meta, info->pass);
	meta_set_used(meta, info->used);
	meta_set_crc(meta, bs);

	rc = pb_write(cfg, meta, p + (1 << info->log2_bpcp) - 1);
	if (rc != 0) {
		goto end;
	}

	memset(meta, 0xff, bs);
end:
	return rc;
}

struct nvb_read_ctx {
	bool direct;
	uint8_t *m;
	uint32_t p;
};

/* Physically write data (uses nvb_read_ctx to fetch from storage or
 * from a buffer).
 */
static int pb_write_data(const struct nvb_config *cfg,
			 struct nvb_read_ctx *ctx, uint32_t p)
{
	if (ctx->direct) {
		return pb_write(cfg, ctx->m, p);
	}

	int rc = pb_read(cfg, cfg->gb, ctx->p);

	if (rc != 0) {
		return rc;
	}

	return pb_write(cfg, cfg->gb, p);
}

/* Recover from a failed write */
static int nvb_recovery(struct nvb_info *info, uint16_t vhead, uint8_t icpe)
{
	const struct nvb_config *cfg = info->cfg;
	const uint8_t spcp = (1 << info->log2_bpcp) - 1;
	const uint32_t prd = vhead << info->log2_bpcp;
	int rc = 0;

	nvb_head_advance(info);
	while (info->cpe < icpe) {
		const uint32_t pwr = info->head << info->log2_bpcp;
		struct nvb_read_ctx ctx = {
			.direct = false,
			.p = prd + info->cpe,
		};

		rc = pb_write_data(cfg, &ctx, pwr + info->cpe);
		if (rc != 0) {
			break;
		}

		info->cpe++;
	}

	if (rc != 0) {
		goto end;
	}

	for (uint8_t cpe = 1; ((cpe <= icpe) && (cpe < spcp)); cpe++) {
		uint8_t *wr_meta_me = meta_me(cfg->mb, cpe);

		for (uint8_t i = 0; i < NVB_CP_MAP_ALT_CNT; i++) {
			if (meta_me_get_alt(wr_meta_me, i) == NVB_BLOCK_NONE) {
				continue;
			}

			if ((vhead < info->head) &&
			    ((meta_me_get_alt(wr_meta_me, i) < vhead) ||
			     (meta_me_get_alt(wr_meta_me, i) > info->head))) {
				continue;
			}

			if ((vhead > info->head) &&
			    (meta_me_get_alt(wr_meta_me, i) < vhead) &&
			    (meta_me_get_alt(wr_meta_me, i) > info->head)) {
				continue;
			}

			meta_me_set_alt(wr_meta_me, info->head, i);
		}
	}
end:
	return rc;
}

/* Write a sector of data and put the meta_me in the meta buffer.
 * Recover on failure.
 */
static int nvb_write_sector(struct nvb_info *info, struct nvb_read_ctx *ctx,
			    uint8_t *data_meta_me)
{
	const struct nvb_config *cfg = info->cfg;
	const uint8_t retries_shift = (cfg->log2_bpeb - info->log2_bpcp);
	const uint8_t spcp = (1 << info->log2_bpcp) - 1;
	uint8_t *wr_meta_me = meta_me(cfg->mb, info->cpe);
	uint16_t retries = ((cfg->sp_eb - 1U) << retries_shift) + 1U;
	uint16_t vhead;
	uint8_t cpe;
	int rc = 0;

	memcpy(wr_meta_me, data_meta_me, NVB_CP_MAP_ENTRY_SIZE);

	vhead = info->head;
	cpe = info->cpe;
	while (retries > 0U) {
		uint32_t p = info->head << info->log2_bpcp;

		rc = pb_write_data(cfg, ctx, p + info->cpe);
		if (rc == 0) {
			break;
		}

		while (retries > 0U) {
			retries--;
			rc = nvb_recovery(info, vhead, cpe);
			if (rc == 0) {
				break;
			}
		}
	}

	if (rc != 0) {
		goto end;
	}

	info->cpe++;

	if (info->cpe != spcp) {
		info->root = info->head;
		goto end;
	}

	vhead = info->head;
	cpe = info->cpe;
	while (retries > 0U) {
		rc = nvb_add_meta(info);
		if (rc == 0) {
			break;
		}

		while (retries > 0U) {
			retries--;
			rc = nvb_recovery(info, vhead, cpe);
			if (rc == 0) {
				break;
			}
		}
	}

	if (rc != 0) {
		goto end;
	}

	info->root = info->head;
	nvb_head_advance(info);
end:
	return rc;
}

/* Move tail data to the front of the logical block solution */
static int nvb_move_tail_data(struct nvb_info *info)
{
	const uint8_t spcp = (1 << info->log2_bpcp) - 1;
	uint8_t *rd, *rd_meta_me;
	uint8_t wr_meta_me[NVB_CP_MAP_ENTRY_SIZE];
	uint16_t target;
	uint32_t p, pe;
	int rc;

	rd = nvb_get_meta(info, info->tail, NULL);
	if (rd == NULL) {
		info->tail_cpe = spcp - 1;
		rc = 0;
		goto end;
	}

	rd_meta_me = meta_me(rd, info->tail_cpe);
	target = meta_me_get_target(rd_meta_me);
	rc = nvb_meta_trace(info, target, &p, wr_meta_me);

	if (rc == -NVB_ENOENT) {
		rc = 0;
		goto end;
	}

	if (rc != 0) {
		goto end;
	}

	pe = (uint32_t)((info->tail << info->log2_bpcp) + info->tail_cpe);
	if (p != pe) {
		goto end;
	}

	struct nvb_read_ctx ctx = {
		.direct = false,
		.p = p,
	};

	rc = nvb_write_sector(info, &ctx, wr_meta_me);
end:
	info->tail_cpe++;
	if (info->tail_cpe == spcp) {
		nvb_advance(info, &info->tail);
		info->tail_cpe = 0U;
	}

	return rc;
}

/* Advance the tail of the logical block solution */
static int nvb_tail_advance(struct nvb_info *info)
{
	int rc = 0;

	while (true) {
		rc = nvb_move_tail_data(info);
		if (rc != 0) {
			goto end;
		}

		if (info->cpe == 0U) {
			break;
		}
	}
end:
	return rc;
}

/* Check if it is required to move data from the tail */
static bool nvb_need_gc(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	const uint32_t sz = cfg->eb << cfg->log2_bpeb;
	const uint32_t asz = (cfg->eb - cfg->sp_eb) << cfg->log2_bpeb;
	const uint32_t pt = (info->tail << info->log2_bpcp) + info->tail_cpe;
	const uint32_t ph = (info->head << info->log2_bpcp) + info->cpe;

	if (ph < pt) {
		return ((ph + sz - pt) >= asz);
	}

	return ((ph - pt) >= asz);
}

/* Automatically perform any required move from the tail */
static int nvb_auto_gc(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	const uint8_t log2_cppeb = cfg->log2_bpeb - info->log2_bpcp;
	const uint32_t max_cnt = (uint32_t)(cfg->eb << log2_cppeb) + 1U;
	uint32_t cnt = 0;
	int rc = 0;

	while ((nvb_need_gc(info)) && (cnt < max_cnt)) {
		rc = nvb_tail_advance(info);
		if (rc != 0) {
			break;
		}

		cnt++;
	}

	if (cnt == max_cnt) {
		rc = -NVB_ENOSPC;
	}

	return rc;
}

/* Calculate the maximum blocks that can be stored as logical blocks */
static uint16_t nvb_max_blocks(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	const uint8_t log2_cppeb = (cfg->log2_bpeb - info->log2_bpcp);
	const uint32_t cp = (cfg->eb - cfg->sp_eb) << log2_cppeb;
	uint32_t bcnt = ((1 << info->log2_bpcp) - 1) * cp;

	bcnt = (bcnt < (1 << 16)) ? bcnt: (1 << 16);

	/* Reduce the maximum allowed blocks with 1 to always allow delete */
	return (uint16_t)(bcnt - 1U);
}

/* Add a block of data to logical block t */
static int nvb_add_block(struct nvb_info *info, uint16_t t, uint8_t *data)
{
	uint8_t wr_meta_me[NVB_CP_MAP_ENTRY_SIZE];
	uint32_t p;
	int rc;

	rc = nvb_auto_gc(info);
	if (rc != 0) {
		goto end;
	}

	rc = nvb_meta_trace(info,t, &p, wr_meta_me);
	if ((rc != 0) && (rc != -NVB_ENOENT)) {
		goto end;
	}

	if (rc == -NVB_ENOENT) {
		if (info->used == nvb_max_blocks(info)) {
			rc = -NVB_ENOSPC;
			goto end;
		}

		info->used++;
	}

	struct nvb_read_ctx ctx = {
		.direct = true,
		.m = data,
	};

	rc = nvb_write_sector(info, &ctx, wr_meta_me);
end:
	return rc;
}

/* Delete a block of data at logical block t */
static int nvb_delete_block(struct nvb_info *info, uint16_t t)
{
	uint8_t del_meta_me[NVB_CP_MAP_ENTRY_SIZE];
	uint8_t *rd, cpe;
	int d = NVB_CP_MAP_ALT_CNT - 1;
	uint16_t altmeta;
	uint32_t p;
	int rc;

	rc = nvb_auto_gc(info);
	if (rc != 0) {
		goto end;
	}

	rc = nvb_meta_trace(info, t, &p, del_meta_me);
	if (rc != 0) {
		goto end;
	}

	while (d >= 0) {
		altmeta = meta_me_get_alt(del_meta_me, d);
		if (altmeta != NVB_BLOCK_NONE) {
			break;
		}

		d--;
	}

	if (d < 0) {
		/* last item deleted */
		for (;;) {
			info->root = NVB_BLOCK_NONE;
			info->used = 0U;
			info->tail = info->head;
			info->tail_cpe = 0U;
			rc = nvb_add_meta(info);
			if (rc == 0) {
				break;
			}

			nvb_head_advance(info);
		}
		goto end;
	}

	/* The candidates for rewrite are in the alt meta block */
	rd = nvb_get_meta(info, altmeta, &cpe);
	if (rd == NULL) {
		goto end;
	}

	while (cpe > 0U) {
		uint8_t *tr_meta_me;
		uint16_t target;
		int dm = 0;

		cpe--;
		tr_meta_me = meta_me(rd, cpe);
		target = meta_me_get_target(tr_meta_me);

		while ((((target ^ t) & d_bit(dm)) == 0U) && (dm < d)) {
			dm++;
		}

		if (((((target ^ t) & d_bit(d)) == 0U)) || (dm < d)) {
			continue;
		}

		rc = nvb_meta_trace(info, target, &p, del_meta_me);
		if (rc == -NVB_ENOENT) {
			continue;
		}

		if (rc != 0) {
			goto end;
		}

		meta_me_set_alt(del_meta_me, NVB_BLOCK_NONE, d);

		struct nvb_read_ctx ctx = {
			.direct = false,
			.p = p,
		};

		rc = nvb_write_sector(info, &ctx, del_meta_me);
		if (rc != 0) {
			goto end;
		}

		break;
	}

	info->used--;
end:
	return rc;
}

/* Read a block of data at logical block t */
static int nvb_read_block(struct nvb_info *info, uint16_t t, uint8_t *data)
{
	uint8_t rd_meta_me[NVB_CP_MAP_ENTRY_SIZE];
	uint32_t p;
	int rc;

	rc = nvb_meta_trace(info, t, &p, rd_meta_me);
	if (rc != 0) {
		goto end;
	}

	rc = pb_read(info->cfg, data, p);
	if (rc != 0) {
		goto end;
	}
end:
	return rc;
}

/* Perform a sync (write of meta) */
static int nvb_sync_block(struct nvb_info *info)
{
	int rc = 0;

	if (info->cpe == 0U) {
		goto end;
	}

	if (info->used == 0U) {
		rc = nvb_add_meta(info);
		nvb_head_advance(info);
		goto end;
	}

	rc = nvb_tail_advance(info);
end:
	return rc;
}

/* Initialize the logical block solution */
static int nvb_raw_init(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	const size_t bs = 1 << cfg->log2_bs;
	uint16_t p_meta = 0U;
	uint8_t *meta = cfg->gb;
	bool valid = false;

	info->log2_bpcp = 0U;

	/* Block size too small to fit 1 checkpoint */
	if (bs < (NVB_CP_MAP_ENTRY_SIZE + NVB_CP_OVERHEAD)) {
		goto end;
	}

	/* Calculate the blocks per checkpoint */
	while (true) {
		uint8_t nme = ((1 << (info->log2_bpcp + 1)) - 1);

		if ((nme * NVB_CP_MAP_ENTRY_SIZE) > (bs - NVB_CP_OVERHEAD)) {
			break;
		}

		info->log2_bpcp++;
	}

	info->root = NVB_BLOCK_NONE;
	info->head = NVB_BLOCK_NONE;
	info->used = 0U;
	info->tail = 0U;
	info->pass = 0U;
	info->cpe = 0U;
	info->tail_cpe = 0U;

	if (cfg->log2_bpeb < info->log2_bpcp) {
		goto end;
	}

	while (p_meta < (cfg->eb << (cfg->log2_bpeb - info->log2_bpcp))) {
		meta = nvb_get_meta(info, p_meta, NULL);
		if (meta == NULL) {
			p_meta++;
			continue;
		}

		if ((info->pass != 0U) &&
		    (info->pass != meta_get_pass(meta))) {
			break;
		}

		valid = true;
		info->pass = meta_get_pass(meta);
		info->used = meta_get_used(meta);
		info->root = p_meta;
		info->head = p_meta;
		info->tail = meta_get_tail(meta);
		info->tail_cpe = meta_get_tail_cpe(meta);
		p_meta++;
	}

	if (info->used == 0U) {
		info->root = NVB_BLOCK_NONE;
	}

	if (valid) {
		nvb_head_advance(info);
	} else {
		info->head = 0;
		info->pass = NVB_CP_PASS_ODD;
	}

	return 0;
end:
	return -NVB_EINVAL;
}

/* Read from (multiple) logical blocks */
int nvb_raw_read(struct nvb_info *info, void *data, uint16_t sblock,
		 uint16_t bcnt)
{
	uint8_t *data8 = (uint8_t *)data;
	int rc;

	while (true) {
		bcnt--;
		rc = nvb_read_block(info, sblock, data8);
		if ((rc != 0) || (bcnt == 0U)) {
			break;
		}

		sblock++;
		data8 += (1 << info->cfg->log2_bs);
	}

	return rc;
}

/* Write to (multiple) logical blocks */
int nvb_raw_write(struct nvb_info *info, const void *data, uint16_t sblock,
	      uint16_t bcnt)
{
	uint8_t *data8 = (uint8_t *)data;
	int rc;

	while (true) {
		bcnt--;
		rc = nvb_add_block(info, sblock, data8);
		if ((rc != 0) || (bcnt == 0U)) {
			break;
		}

		sblock++;
		data8 += (1 << info->cfg->log2_bs);
	}

	return rc;
}

/* Delete (multiple) logical blocks */
int nvb_raw_delete(struct nvb_info *info, uint16_t sblock, uint16_t bcnt)
{
	int rc;

	while (true) {
		bcnt--;
		rc = nvb_delete_block(info, sblock);
		if ((rc != 0) || (bcnt == 0U)) {
			break;
		}

		sblock++;
	}

	if (rc != 0) {
		goto end;
	}

	if (info->used == 0U) {
		info->tail = info->head;
		info->tail_cpe = 0U;

	}
end:
	return rc;
}

int nvb_raw_sync(struct nvb_info *info)
{
	return nvb_sync_block(info);
}

/* Get and set some basic properties of the logical block solution */
int nvb_raw_ioctl(struct nvb_info *info, uint8_t cmd, void *buffer)
{
	switch(cmd) {
	case NVB_CMD_GET_BLK_COUNT:
	 	*(uint32_t *)buffer = (uint32_t)nvb_max_blocks(info);
		break;
	case NVB_CMD_GET_BLK_SIZE:
		*(uint32_t *)buffer = (1 << info->cfg->log2_bs);
		break;
	case NVB_CMD_GET_VERSION:
		*(uint32_t *)buffer = NVB_VERSION;
		break;
	default:
		return -NVB_EINVAL;
	}

	return 0;
}

/* Public API routines for the logical block solution */
/* Initialize the logical block system */
int nvb_init(struct nvb_info *info, const struct nvb_config *cfg)
{
	if ((info == NULL) || (cfg == NULL) ||
	    (cfg->read == NULL) || (cfg->prog == NULL) ||
	    (cfg->mb == NULL) || (cfg->gb == NULL)) {
		return -NVB_EINVAL;
	}

	if (info->cfg != NULL) {
		return -NVB_EAGAIN;
	}

	if ((cfg->log2_bs == 0) || (cfg->log2_bpeb == 0) ||
	    (cfg->eb <= cfg->sp_eb) || (cfg->sp_eb == 0)) {
		return -NVB_EINVAL;
	}

	int rc;

	rc = cfg_init(cfg);
	if (rc != 0) {
		return rc;
	}

	rc = cfg_lock(cfg);
	if (rc != 0) {
		return rc;
	}

	info->cfg = cfg;
	rc = nvb_raw_init(info);
	if (rc != 0) {
		info->cfg = NULL;
		goto end;
	}

	info->read = nvb_raw_read;
	info->write = nvb_raw_write;
	info->delete = nvb_raw_delete;
	info->sync = nvb_raw_sync;
	info->ioctl = nvb_raw_ioctl;

end:
	(void)cfg_unlock(cfg);
	return rc;
}

/* Initialize the logical block system */
int nvb_init_ro(struct nvb_info *info, const struct nvb_config *cfg)
{
	if ((info == NULL) || (cfg == NULL) ||
	    (cfg->read == NULL) || (cfg->gb == NULL)) {
		return -NVB_EINVAL;
	}

	if (info->cfg != NULL) {
		return -NVB_EAGAIN;
	}

	if ((cfg->log2_bs == 0) || (cfg->log2_bpeb == 0) ||
	    (cfg->eb == 0)) {
		return -NVB_EINVAL;
	}

	int rc;

	rc = cfg_init(cfg);
	if (rc != 0) {
		return rc;
	}

	rc = cfg_lock(cfg);
	if (rc != 0) {
		return rc;
	}

	info->cfg = cfg;
	rc = nvb_raw_init(info);
	if (rc != 0) {
		info->cfg = NULL;
		goto end;
	}

	info->read = nvb_raw_read;
	info->write = NULL;
	info->delete = NULL;
	info->sync = NULL;
	info->ioctl = nvb_raw_ioctl;

end:
	(void)cfg_unlock(cfg);
	return rc;
}

/* Deinitialize the logical block system */
int nvb_deinit(struct nvb_info *info)
{
	if (info == NULL) {
		return -NVB_EINVAL;
	}

	if (info->cfg == NULL) {
		return 0;
	}

	const struct nvb_config *cfg = info->cfg;
	int rc;

	rc = cfg_lock(cfg);
	if (rc != 0) {
		goto end;
	}

	rc = cfg_deinit(cfg);
	info->cfg = NULL;
	info->read = NULL;
	info->write = NULL;
	info->delete = NULL;
	info->sync = NULL;
	info->ioctl = NULL;

end:
	return rc;
}

/* Read from (multiple) logical blocks */
int nvb_read(struct nvb_info *info, void *data, uint16_t sblock, uint16_t bcnt)
{
	if ((info == NULL) || (info->read == NULL)) {
		return -NVB_EINVAL;
	}

	const struct nvb_config *cfg = info->cfg;
	int rc;

	rc = cfg_lock(cfg);
	if (rc != 0) {
		goto end;
	}

	rc = info->read(info, data, sblock, bcnt);
	(void)cfg_unlock(cfg);
end:
	return rc;
}

/* Write to (multiple) logical blocks */
int nvb_write(struct nvb_info *info, const void *data, uint16_t sblock,
	      uint16_t bcnt)
{
	if ((info == NULL) || (info->write == NULL)) {
		return -NVB_EINVAL;
	}

	const struct nvb_config *cfg = info->cfg;
	int rc;

	rc = cfg_lock(cfg);
	if (rc != 0) {
		goto end;
	}

	rc = info->write(info, data, sblock, bcnt);
	(void)cfg_unlock(cfg);
end:
	return rc;
}

/* Delete (multiple) logical blocks */
int nvb_delete(struct nvb_info *info, uint16_t sblock, uint16_t bcnt)
{
	if ((info == NULL) || (info->delete == NULL)) {
		return -NVB_EINVAL;
	}

	const struct nvb_config *cfg = info->cfg;
	int rc;

	rc = cfg_lock(cfg);
	if (rc != 0) {
		goto end;
	}

	rc = info->delete(info, sblock, bcnt);
	(void)cfg_unlock(cfg);
end:
	return rc;
}

/* Sync data to storage */
int nvb_sync(struct nvb_info *info)
{
	const struct nvb_config *cfg = info->cfg;
	int rc;

	rc = cfg_lock(cfg);
	if (rc != 0) {
		goto end;
	}

	rc = info->sync(info);
	(void)cfg_unlock(cfg);
end:
	return rc;
}

/* Get and set some basic properties of the logical block solution */
int nvb_ioctl(struct nvb_info *info, uint8_t cmd, void *buffer)
{
	if ((info == NULL) || (info->ioctl == NULL)) {
		return -NVB_EINVAL;
	}

	const struct nvb_config *cfg = info->cfg;
	int rc;

	rc = cfg_lock(cfg);
	if (rc != 0) {
		goto end;
	}

	rc = info->ioctl(info, cmd, buffer);
	(void)cfg_unlock(cfg);
end:
	return rc;
}
