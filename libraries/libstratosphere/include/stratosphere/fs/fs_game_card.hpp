/*
 * Copyright (c) 2018-2020 Atmosphère-NX
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#pragma once
#include "fs_common.hpp"

namespace ams::fs {

    enum class GameCardPartition {
        Update = 0,
        Normal = 1,
        Secure = 2,
        Logo   = 3,
    };

    enum class GameCardPartitionRaw {
        NormalReadable,
        SecureReadable,
        RootWriteable,
    };

    enum class GameCardAttribute : u8 {
        AutoBootFlag                         = (1 << 0),
        HistoryEraseFlag                     = (1 << 1),
        RepairToolFlag                       = (1 << 2),
        DifferentRegionCupToTerraDeviceFlag  = (1 << 3),
        DifferentRegionCupToGlobalDeviceFlag = (1 << 4),
    };

#define MAGIC_HEAD 0x44414548 /* "HEAD" */
#define MAGIC_HFS0 0x30534648 /* "HFS0" */

    typedef struct
    {
        uint8_t header_sig[0x100];
        uint32_t magic;
        uint32_t secure_offset;
        uint32_t _0x108;
        uint8_t _0x10C;
        uint8_t cart_type;
        uint8_t _0x10E;
        uint8_t _0x10F;
        uint64_t _0x110;
        uint64_t cart_size;
        unsigned char reversed_iv[0x10];
        uint64_t hfs0_offset;
        uint64_t hfs0_header_size;
        unsigned char hfs0_header_hash[0x20];
        unsigned char crypto_header_hash[0x20];
        uint32_t _0x180;
        uint32_t _0x184;
        uint32_t _0x188;
        uint32_t _0x18C;
        unsigned char encrypted_data[0x70];
    } GamecardHeader;
    static_assert(sizeof(GamecardHeader) == 0x200, "GamecardHeader has incorrect size.");
    
    typedef struct 
    {
        uint32_t magic;
        uint32_t num_files;
        uint32_t string_table_size;
        uint32_t reserved;
    } HFS0BaseHeader;
    static_assert(sizeof(HFS0BaseHeader) == 0x10, "HFS0BaseHeader must be 0x10");

    typedef struct
    {
        uint64_t offset;
        uint64_t size;
        uint32_t string_table_offset;
        uint32_t hashed_size;
        uint64_t reserved;
        unsigned char hash[0x20];
    } HFS0FileEntry;
    static_assert(sizeof(HFS0FileEntry) == 0x40, "HFS0FileEntry must be 0x18");

    using GameCardHandle = u32;

    Result GetGameCardHandle(GameCardHandle *out);
    Result MountGameCardPartition(const char *name, GameCardHandle handle, GameCardPartition partition);

}
