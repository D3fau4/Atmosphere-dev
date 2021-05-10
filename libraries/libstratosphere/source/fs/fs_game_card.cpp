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
#include <stratosphere.hpp>
#include "fsa/fs_mount_utils.hpp"

namespace ams::fs
{

    namespace
    {

        const char *GetGameCardMountNameSuffix(GameCardPartition which)
        {
            switch (which)
            {
            case GameCardPartition::Update:
                return impl::GameCardFileSystemMountNameUpdateSuffix;
            case GameCardPartition::Normal:
                return impl::GameCardFileSystemMountNameNormalSuffix;
            case GameCardPartition::Secure:
                return impl::GameCardFileSystemMountNameSecureSuffix;
                AMS_UNREACHABLE_DEFAULT_CASE();
            }
        }

        class GameCardCommonMountNameGenerator : public fsa::ICommonMountNameGenerator, public impl::Newable
        {
        private:
            const GameCardHandle handle;
            const GameCardPartition partition;

        public:
            explicit GameCardCommonMountNameGenerator(GameCardHandle h, GameCardPartition p) : handle(h), partition(p)
            { /* ... */
            }

            virtual Result GenerateCommonMountName(char *dst, size_t dst_size) override
            {
                /* Determine how much space we need. */
                const size_t needed_size = strnlen(impl::GameCardFileSystemMountName, MountNameLengthMax) + strnlen(GetGameCardMountNameSuffix(this->partition), MountNameLengthMax) + sizeof(GameCardHandle) * 2 + 2;
                AMS_ABORT_UNLESS(dst_size >= needed_size);

                    /* Generate the name. */
                    auto size = util::SNPrintf(dst, dst_size, "%s%s%08x:", impl::GameCardFileSystemMountName, GetGameCardMountNameSuffix(this->partition), this->handle);
                    AMS_ASSERT(static_cast<size_t>(size) == needed_size - 1);

                return ResultSuccess();
            }
        };

    } // namespace
    constexpr const char *const NCMSdMountName = "#NCMsdpatch";
    os::Mutex g_ldr_sd_lock(false);
    bool g_mounted_sd;

    bool EnsureSdCardMounted()
    {
        std::scoped_lock lk(g_ldr_sd_lock);

        if (g_mounted_sd)
        {
            return true;
        }

        if (!cfg::IsSdCardInitialized())
        {
            return false;
        }

        if (R_FAILED(fs::MountSdCard(NCMSdMountName)))
        {
            return false;
        }

        return (g_mounted_sd = true);
    }

    static inline HFS0FileEntry *hfs0_get_file_entry(HFS0BaseHeader *hdr, uint32_t i)
    {
        if (i >= hdr->num_files)
            return NULL;
        return (HFS0FileEntry *)((char *)(hdr) + sizeof(*hdr) + i * sizeof(HFS0FileEntry));
    }

    static inline char *hfs0_get_string_table(HFS0BaseHeader *hdr)
    {
        return (char *)(hdr) + sizeof(*hdr) + hdr->num_files * sizeof(HFS0FileEntry);
    }

    static inline uint64_t hfs0_get_header_size(HFS0BaseHeader *hdr)
    {
        return sizeof(*hdr) + hdr->num_files * sizeof(HFS0FileEntry) + hdr->string_table_size;
    }

    static inline char *hfs0_get_file_name(HFS0BaseHeader *hdr, uint32_t i)
    {
        return hfs0_get_string_table(hdr) + hfs0_get_file_entry(hdr, i)->string_table_offset;
    }

    Result GetGameCardHandle(GameCardHandle *out)
    {
        /* TODO: fs::DeviceOperator */
        /* Open a DeviceOperator. */
        ::FsDeviceOperator d;
        R_TRY(fsOpenDeviceOperator(std::addressof(d)));
        ON_SCOPE_EXIT { fsDeviceOperatorClose(std::addressof(d)); };

        /* Get the handle. */
        static_assert(sizeof(GameCardHandle) == sizeof(::FsGameCardHandle));
        return fsDeviceOperatorGetGameCardHandle(std::addressof(d), reinterpret_cast<::FsGameCardHandle *>(out));
    }

    Result Create(std::shared_ptr<fs::fsa::IFileSystem> *out,std::shared_ptr<fs::IStorage> storage) {
        /* Allocate a filesystem. */
        //std::shared_ptr fs = fssystem::AllocateShared<fssystem::Sha256PartitionFileSystem>();
        //R_UNLESS(fs != nullptr, fs::ResultAllocationFailureInPartitionFileSystemCreatorA());

        /* Initialize the filesystem. */
        //R_TRY(fs->Initialize(std::move(storage)));

        /* Set the output. */
        //*out = std::move(fs);
        return ResultSuccess();
    }

    std::shared_ptr<fs::fsa::IFileSystem> Secure1;
    bool MountSDcard()
    {
        /* Vars */
        char path[fs::EntryNameLengthMax + 1];

        /* GameCard Image */
        fs::IStorage *GamecardImage;

        /* HFS0 Images */
        fs::SubStorage *hfs0root;
        fs::SubStorage *hfs0Update;
        fs::SubStorage *hfs0Normal;
        fs::SubStorage *hfs0Secure;
        fs::SubStorage *hfs0Logo;

        /* HFS0 Headers */
        GamecardHeader xciheader;
        HFS0BaseHeader rootheader;
        HFS0BaseHeader Secureheader;

        /* Root Partitions Entrys */
        HFS0FileEntry UpdateEntry;
        HFS0FileEntry NormalEntry;
        HFS0FileEntry *SecureEntry;
        HFS0FileEntry LogoEntry;

        /* IFileSystem GameCard Partition */
        
        

        /* Open the file. */
        fs::FileHandle file;
        std::snprintf(path, sizeof(path), "%s:/D3fOS/%s", NCMSdMountName, "meme.xci");
        if (R_SUCCEEDED(fs::OpenFile(std::addressof(file), path, fs::OpenMode_Read)))
        {
            // Convert FileHandle to IStorage
            auto tmp = std::shared_ptr<IStorage>(new FileHandleStorage(file));
            GamecardImage = tmp.get();
            // Read XCI header
            GamecardImage->Read(0x0, std::addressof(xciheader), 0x200);
            if (xciheader.magic == MAGIC_HEAD)
            {
                s64 GamecardImageSize;
                GamecardImage->GetSize(&GamecardImageSize);
                // Open root partition header as SubStorage
                hfs0root = new fs::SubStorage(GamecardImage, xciheader.hfs0_offset, GamecardImageSize - xciheader.hfs0_offset);
                // Read global header
                hfs0root->Read(0x0, std::addressof(rootheader), sizeof(HFS0BaseHeader));
                hfs0root->Read(0x0, std::addressof(rootheader), hfs0_get_header_size(&rootheader));
                if (rootheader.magic == MAGIC_HFS0)
                {
                    SecureEntry = hfs0_get_file_entry(&rootheader, (uint32_t)fs::GameCardPartition::Secure);
                    hfs0Secure = new fs::SubStorage(hfs0root, SecureEntry->offset, SecureEntry->size);
                    hfs0Secure->Read(0x0, std::addressof(Secureheader), sizeof(HFS0BaseHeader));
                    hfs0Secure->Read(0x0, std::addressof(Secureheader), hfs0_get_header_size(&rootheader));
                    if (Secureheader.magic == MAGIC_HFS0) {
                        auto meme = std::shared_ptr<IStorage>(hfs0Secure);
                        Create(&Secure1,meme);
                        return true;
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                fs::CloseFile(file);
                return false;
            }
        }
        else
        {
            fs::CloseFile(file);
            return false;
        }
    }

    Result MountGameCardPartition(const char *name, GameCardHandle handle, GameCardPartition partition)
    {
        /* Validate the mount name. */
        R_TRY(impl::CheckMountNameAllowingReserved(name));

        ::FsFileSystem fs;
        const ::FsGameCardHandle _hnd = {handle};

        /* Open gamecard filesystem. This uses libnx bindings. */
        if (!EnsureSdCardMounted())
        {
            return 0;
        }
        else
        {
            if (MountSDcard() == true) {
                R_TRY(fsOpenGameCardFileSystem(std::addressof(fs), std::addressof(_hnd), static_cast<::FsGameCardPartition>(partition)));
            }
        }

        fssystem::AllocateShared<fssystem::Sha256PartitionFileSystem>();

        /* Allocate a new filesystem wrapper. */
        auto fsa = std::make_unique<RemoteFileSystem>(fs);
        R_UNLESS(fsa != nullptr, fs::ResultAllocationFailureInGameCardC());

        /* Allocate a new mountname generator. */
        auto generator = std::make_unique<GameCardCommonMountNameGenerator>(handle, partition);
        R_UNLESS(generator != nullptr, fs::ResultAllocationFailureInGameCardD());

        /* Register. */
        return fsa::Register(name, std::move(fsa), std::move(generator));
    }

} // namespace ams::fs
