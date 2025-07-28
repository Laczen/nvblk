/*
 * NVBLK: A logical block system for non volatile memory.
 *
 * The system creates a block IO device for "smaller" flash devices. The base
 * (physical) block size is defined in the non volatile backend and is
 * limited to power of 2 values defined as 2**log2_bs. A number of blocks
 * is stored together with a checkpoint (meta) block. Based upon the physical
 * block size the system calculates an optimal blocks per checkpoint during
 * initialization. The number of blocks per checkpoint + the checkpoint block
 * is limited to a power of 2 (2**log2_bpcp).
 *
 * The system is similar to the dhara wear levelling library but is designed
 * for smaller non volatile memories (e.g. nor flash, eeprom or nvram).
 *
 * The system supports up to 65536 logical blocks that are defined on a
 * non volatile memory up to 65535 * (2**log_bs) * (2**log2_bpcp). There can
 * however be only 65535 logical blocks in use.
 *
 * The system handles bad blocks without keeping track of where the bad blocks
 * are located. Whenever a bad block is written to the system will recover from
 * this as long as sufficient spare erase blocks are available.
 *
 * The user needs to define the backend properties and routines as defined by
 * the struct `nvb_config`, this struct can be embedded in a `device` struct
 * as only a pointer to `nvb_config` is used. As part of the backend
 * properties a pointer to two block sized buffers needs to be provided. The
 * first block size buffer (*gb) is used for processing and block copy, the
 * second block size buffer (*mb) is used for caching the meta or checkpoint
 * information.
 *
 * Copyright (c) 2025 Laczen
 * Copyright (c) 2013 Daniel Beer <dlbeer@gmail.com>
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef NVBLOCK_H
#define NVBLOCK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define NVB_CP_MAGIC "!NVB"

enum {
	NVB_VERSION_MAJOR = 0,
	NVB_VERSION_MINOR = 0,
	NVB_VERSION_REVISION = 1,
	NVB_VERSION = ((NVB_VERSION_MAJOR & 0xff) << 24) |
		      ((NVB_VERSION_MINOR & 0xff) << 16) |
		      (NVB_VERSION_REVISION & 0xffff),
	NVB_BLOCK_NONE = 0xffff,
	NVB_PBLOCK_NONE = 0xffffffff,
	/* MAGIC = "!NVB" is added to the start of each checkpoint */
	NVB_CP_MAGIC_START = 0,
	NVB_CP_MAGIC_SIZE = sizeof(NVB_CP_MAGIC) - 1,
	/* VERSION contains the NVB version */
	NVB_CP_VERSION_START = NVB_CP_MAGIC_START + NVB_CP_MAGIC_SIZE,
	NVB_CP_VERSION_SIZE = 4,
	/* TAIL contains the oldest CP still in use (uint16_t) */
	NVB_CP_TAIL_START = NVB_CP_VERSION_START + NVB_CP_VERSION_SIZE,
	NVB_CP_TAIL_SIZE = 2,
	/* TAIL entry contains the still valid entry of the TAIL */
	NVB_CP_TAIL_ENTRY_START = NVB_CP_TAIL_START + NVB_CP_TAIL_SIZE,
	NVB_CP_TAIL_ENTRY_SIZE = 1,
	/* PASS contains 0x0F on even passes, 0xF0 on odd passes */
	NVB_CP_PASS_EVEN = 0x0f,
	NVB_CP_PASS_ODD = 0xf0,
	NVB_CP_PASS_START = NVB_CP_TAIL_ENTRY_START + NVB_CP_TAIL_ENTRY_SIZE,
	NVB_CP_PASS_SIZE = 1,
	/* USED contains the number of blocks in use (uint16_t) */
	NVB_CP_USED_START = NVB_CP_PASS_START + NVB_CP_PASS_SIZE,
	NVB_CP_USED_SIZE = 2,
	/* MAP starts after USED */
	NVB_CP_MAP_START = NVB_CP_USED_START + NVB_CP_USED_SIZE,
	NVB_CP_MAP_TARGET_SIZE = 2,
	NVB_CP_MAP_ALT_CNT = 16,
	NVB_CP_MAP_ALT_SIZE = 2,
	NVB_CP_MAP_ENTRY_SIZE = NVB_CP_MAP_TARGET_SIZE +
				NVB_CP_MAP_ALT_CNT * NVB_CP_MAP_ALT_SIZE,
	/* At the end of a CP block a 32 bit crc is added */
	NVB_CP_CRC_INIT = 0xffff,
        NVB_CP_CRC_SIZE = 4,
	/* Overhead of a CP block */
	NVB_CP_OVERHEAD = NVB_CP_MAP_START + NVB_CP_CRC_SIZE,
};

enum nvb_error {
	NVB_ENOENT = 2,	 /**< No such file or directory */
	NVB_EFAULT = 14, /**< Bad address */
	NVB_EINVAL = 22, /**< Invalid argument */
	NVB_ENOSPC = 28, /**< No space left on device */
	NVB_EROFS = 30,	 /**< Read-only file system */
	NVB_EAGAIN = 11, /**< No more contexts */
};

/* IOCTL commands codes*/
enum nvb_cmd {
	NVB_CMD_GET_BLK_COUNT = 0x01,
	NVB_CMD_GET_BLK_SIZE = 0x02,
	NVB_CMD_GET_VERSION = 0x04,
};

/** @brief Configuration structure for the logical block system */
struct nvb_config {

	uint8_t *gb;	/**< Generic buffer (block sized) */
	uint8_t *mb;	/**< Metadata buffer (block sized) */

#ifdef NVB_CFG_THREADSAFE
	/* lock (optional): blocks execution for other threads */
	int (*lock)(const struct nvb_config *cfg);

	/* unlock (optional): unblocks execution for other threads */
	int (*unlock)(const struct nvb_config *cfg);
#endif

#ifdef NVB_CFG_INITDEINIT
	/* Initialize routine (optional). For systems that provide thread safety
	 * using a lock mechanism the lock should be initialized in the routine.
	 *
	 * Should return 0 on success, -ERRNO on failure.
	 */
	int (*init)(const struct nvb_config *cfg);

	/* Deinitialize routine (optional). Release all assigned resources.
	 * When a lock mechanism is used the lock will be taken prior to calling
	 * the deinit routine. The deinit routine should therefore also release
	 * the lock before (optionally) destroying the lock.
	 *
	 * Should return 0 on success, -ERRNO on failure.
	 */
	int (*deinit)(const struct nvb_config *cfg);
#endif

	/* Read a physical block at location p (the physical block size can
	 * be retrieved from cfg).
	 *
	 * Should return 0 on success, -ERRNO on failure.
	 */
	int (*read)(const struct nvb_config *cfg, uint32_t p, void *buffer);

	/* Program a physical block at location p (the physical block size can
	 * be retrieved from cfg). When working on memory that needs to be
	 * erased before programming the function needs to erase a block when
	 * a program is performed to the first block of an eraseblock. The
	 * program function is responsible for validating the correctness of
	 * the write and should return an error (e.g. -NVB_EFAULT) on failure.
	 * When used on devices where bad blocks are expected (e.g. nand flash)
	 * the function needs to return an error when trying to write a bad
	 * block.
	 *
	 * Should return 0 on success, -ERRNO on failure.
	 */
	int (*prog)(const struct nvb_config *cfg, uint32_t p,
		    const void *buffer);

	uint8_t log2_bs;	/**< log 2 of block size */
	uint8_t log2_bpeb;	/**< log 2 of blocks per erase block size */
	uint16_t eb;		/**< number of erase blocks */
	uint16_t sp_eb;		/**< spare erase blocks */
};

/** @brief Info structure for the logical block system */
struct nvb_info {
	struct nvb_config const *cfg;

	uint16_t root;		/**< Root checkpoint location */
	uint16_t head;		/**< Current checkpoint location of head */
	uint16_t tail;		/**< Checkpoint of tail */
	uint16_t used;		/**< Number of blocks in use */

	uint8_t pass;		/**< 0x0F on even passes, 0xF0 on odd passes */
	uint8_t log2_bpcp;	/**< blocks per checkpoint (incl meta block) */
	uint8_t cpe;		/**< current checkpoint entry of head */
	uint8_t tail_cpe;	/**< current checkpoint entry of tail */

	/* API routines, should not be used directly */

	/* Read data from logical blocks. */
	int (*read)(struct nvb_info *info, void *data, uint16_t sblock,
		    uint16_t bcnt);

	/* Write data to logical blocks. */
	int (*write)(struct nvb_info *info, const void *data, uint16_t sblock,
		    uint16_t bcnt);

	/* Delete logical blocks. */
	int (*delete)(struct nvb_info *info, uint16_t sblock, uint16_t bcnt);

	/* Sync data to storage. */
	int (*sync)(struct nvb_info *info);

	/* ioctl for logical blocks */
	int (*ioctl)(struct nvb_info *info, uint8_t cmd, void *buff);
};

/**
 * @brief Initialize the logical block system object
 *
 * Initializes the nvb_info object; the function needs to be invoked on object
 * before first use. A configuration structure needs to be passed to the
 * initialize routine.
 *
 * @param info Pointer to logical block object
 * @param cfg Pointer to logical block configuration object
 *
 * @retval 0 on success, -ERRNO otherwise.
 *
 */
int nvb_init(struct nvb_info *info, const struct nvb_config *cfg);

/**
 * @brief Initialize the logical block system object for read-only
 *
 * Specific initialization method for read-only usage. The function needs to be
 * invoked on object before first use. A configuration structure needs to be
 * passed to the initialize routine.
 *
 * @param info Pointer to logical block object
 * @param cfg Pointer to logical block configuration object
 *
 * @retval 0 on success, -ERRNO otherwise.
 *
 */
int nvb_init_ro(struct nvb_info *info, const struct nvb_config *cfg);

/**
 * @brief Deinitialize the logical block system object
 *
 * Deinitializes the nvb_info object.
 *
 * @param info Pointer to logical block object
 *
 * @retval 0 on success, -ERRNO otherwise.
 *
 */
int nvb_deinit(struct nvb_info *info);

/**
 * @brief Read data from logical blocks
 *
 * Read data from logical blocks.
 *
 * @param info Pointer to logical block object
 * @param data Pointer to read result buffer
 * @param sblock Start block to read
 * @param bcnt Number of blocks to read
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
int nvb_read(struct nvb_info *info, void *data, uint16_t sblock, uint16_t bcnt);

/**
 * @brief Write data to logical blocks
 *
 * Write data to logical blocks.
 *
 * @param info Pointer to logical block object
 * @param data Pointer to data
 * @param sblock Start block to write
 * @param bcnt Number of blocks to write
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
int nvb_write(struct nvb_info *info, const void *data, uint16_t sblock,
	      uint16_t bcnt);

/**
 * @brief Delete logical blocks
 *
 * Delete logical blocks.
 *
 * @param info Pointer to logical block object
 * @param sblock Start block to delete
 * @param bcnt Number of blocks to delete
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
 int nvb_delete(struct nvb_info *info, uint16_t sblock, uint16_t bcnt);

 /**
 * @brief Sync data to storage
 *
 * Sync data to storage (add checkpoint).
 *
 * @param info Pointer to logical block object
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
 int nvb_sync(struct nvb_info *info);

 /**
 * @brief IOCTL interface for a logical block object
 *
 * @param info Pointer to logical block object
 * @param cmd command number
 * @param buff Pointer to command info/command result
 *
 * @retval 0 on success, -ERRNO otherwise.
 */
int nvb_ioctl(struct nvb_info *info, uint8_t cmd, void *buff);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* NVBLOCK_H */