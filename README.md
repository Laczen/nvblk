Non volatile logical block device with wear levelling

The system provides a block IO device for "smaller" flash devices. The base
(physical) block size is defined in the non volatile backend and is
limited to power of 2 values defined as 2**log2_bs. A number of blocks
is stored together with a checkpoint (meta) block. Based upon the physical
block size the system calculates an optimal blocks per checkpoint during
initialization. The number of blocks per checkpoint + the checkpoint block
is limited to a power of 2 (`2**log2_bpcp`).

The system is similar to the dhara wear levelling library but is designed
for smaller non volatile memories (e.g. nor flash, eeprom or nvram).
The dhara wear levelling library was used as source of inspiration and the
system shares many properties (e.g. the alt pointers) with dhara. The
author expresses gratitude towards the excellent dhara wear levelling
library.

The system supports up to 65536 logical blocks that are defined on a
non volatile memory up to `65535 * (2**log_bs) * (2**log2_bpcp)`. There can
however be only 65535 logical blocks in use.

A natural size for the logical blocks is 256 byte which is used as a page-
size on many spi nor flash devices. Selecting a block size of 256 byte results
in a overhead of 1 extra block (a checkpoint or meta block) for each 7 logical
blocks.

The logical block system can be partitioned by reserving ranges of logical
blocks to partitions.

The system handles bad blocks without keeping track of where the bad blocks
are located. Whenever a bad block is written to the system will recover from
this as long as sufficient spare erase blocks are available.

The user needs to define the backend properties and routines as defined by
the struct `nvb_config`, this struct can be embedded in a `device` struct
as only a pointer to `nvb_config` is used. As part of the backend
properties a pointer to two block sized buffers needs to be provided. The
first block size buffer (*gb) is used for processing and block copy, the
second block size buffer (*mb) is used for caching the meta or checkpoint
information.

More information on how to setup the `nvb_config` structure can be found
in [nvblk.h](./include/nvblk/nvblk.h).

The system is accompagnied with [tests](./test) based upon
[Unity Test](https://https://github.com/ThrowTheSwitch/Unity).

