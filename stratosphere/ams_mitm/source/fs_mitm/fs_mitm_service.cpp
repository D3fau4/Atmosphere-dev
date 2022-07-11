/*
 * Copyright (c) Atmosphère-NX
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
#include "../amsmitm_fs_utils.hpp"
#include "../amsmitm_initialization.hpp"
#include "fs_shim.h"
#include "fs_mitm_service.hpp"
#include "fsmitm_boot0storage.hpp"
#include "fsmitm_calibration_binary_storage.hpp"
#include "fsmitm_layered_romfs_storage.hpp"
#include "fsmitm_save_utils.hpp"
#include "fsmitm_readonly_layered_filesystem.hpp"

namespace ams::mitm::fs {

    using namespace ams::fs;

    namespace {

        constexpr const ams::fs::Path AtmosphereHblWebContentDirPath = fs::MakeConstantPath("/atmosphere/hbl_html/");
        constexpr const char ProgramWebContentDir[] = "/manual_html/";

        constinit os::SdkMutex g_boot0_detect_lock;
        constinit bool g_detected_boot0_kind = false;
        constinit bool g_is_boot0_custom_public_key = false;

        constinit fssrv::impl::ProgramIndexMapInfoManager g_program_index_map_info_manager;

        bool IsBoot0CustomPublicKey(::FsStorage &storage) {
            if (AMS_UNLIKELY(!g_detected_boot0_kind)) {
                std::scoped_lock lk(g_boot0_detect_lock);

                if (AMS_LIKELY(!g_detected_boot0_kind)) {
                    g_is_boot0_custom_public_key = DetectBoot0CustomPublicKey(storage);
                    g_detected_boot0_kind = true;
                }
            }

            return g_is_boot0_custom_public_key;
        }

        bool GetSettingsItemBooleanValue(const char *name, const char *key) {
            u8 tmp = 0;
            AMS_ABORT_UNLESS(settings::fwdbg::GetSettingsItemValue(std::addressof(tmp), sizeof(tmp), name, key) == sizeof(tmp));
            return (tmp != 0);
        }

        template<typename... Arguments>
        constexpr ALWAYS_INLINE auto MakeSharedFileSystem(Arguments &&... args) {
            return sf::CreateSharedObjectEmplaced<ams::fssrv::sf::IFileSystem, ams::fssrv::impl::FileSystemInterfaceAdapter>(std::forward<Arguments>(args)...);
        }

        template<typename... Arguments>
        constexpr ALWAYS_INLINE auto MakeSharedStorage(Arguments &&... args) {
            return sf::CreateSharedObjectEmplaced<ams::fssrv::sf::IStorage, ams::fssrv::impl::StorageInterfaceAdapter>(std::forward<Arguments>(args)...);
        }

        Result OpenHblWebContentFileSystem(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> &out, ncm::ProgramId program_id) {
            /* Verify eligibility. */
            bool is_hbl;
            R_UNLESS(R_SUCCEEDED(pm::info::IsHblProgramId(std::addressof(is_hbl), program_id)), sm::mitm::ResultShouldForwardToSession());
            R_UNLESS(is_hbl,                                                     sm::mitm::ResultShouldForwardToSession());

            /* Hbl html directory must exist. */
            {
                FsDir d;
                R_UNLESS(R_SUCCEEDED(mitm::fs::OpenSdDirectory(std::addressof(d), AtmosphereHblWebContentDirPath.GetString(), fs::OpenDirectoryMode_Directory)), sm::mitm::ResultShouldForwardToSession());
                fsDirClose(std::addressof(d));
            }

            /* Open the SD card using fs.mitm's session. */
            FsFileSystem sd_fs;
            R_TRY(fsOpenSdCardFileSystem(std::addressof(sd_fs)));
            const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(sd_fs.s))};
            std::unique_ptr<fs::fsa::IFileSystem> sd_ifs = std::make_unique<fs::RemoteFileSystem>(sd_fs);

            auto subdir_fs = std::make_unique<fssystem::SubDirectoryFileSystem>(std::move(sd_ifs));
            R_TRY(subdir_fs->Initialize(AtmosphereHblWebContentDirPath));

            out.SetValue(MakeSharedFileSystem(std::make_shared<fs::ReadOnlyFileSystem>(std::move(subdir_fs)), false), target_object_id);
            R_SUCCEED();
        }

        Result OpenProgramSpecificWebContentFileSystem(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> &out, ncm::ProgramId program_id, FsFileSystemType filesystem_type, Service *fwd, const fssrv::sf::Path *path, bool with_id) {
            /* Directory must exist. */
            {
                FsDir d;
                R_UNLESS(R_SUCCEEDED(mitm::fs::OpenAtmosphereSdDirectory(std::addressof(d), program_id, ProgramWebContentDir, fs::OpenDirectoryMode_Directory)), sm::mitm::ResultShouldForwardToSession());
                fsDirClose(std::addressof(d));
            }

            /* Open the SD card using fs.mitm's session. */
            FsFileSystem sd_fs;
            R_TRY(fsOpenSdCardFileSystem(std::addressof(sd_fs)));
            const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(sd_fs.s))};
            std::unique_ptr<fs::fsa::IFileSystem> sd_ifs = std::make_unique<fs::RemoteFileSystem>(sd_fs);

            /* Format the subdirectory path. */
            char program_web_content_raw_path[0x100];
            FormatAtmosphereSdPath(program_web_content_raw_path, sizeof(program_web_content_raw_path), program_id, ProgramWebContentDir);

            ams::fs::Path program_web_content_path;
            R_TRY(program_web_content_path.SetShallowBuffer(program_web_content_raw_path));

            /* Make a new filesystem. */
            {
                auto subdir_fs = std::make_unique<fssystem::SubDirectoryFileSystem>(std::move(sd_ifs));
                R_TRY(subdir_fs->Initialize(program_web_content_path));

                std::shared_ptr<fs::fsa::IFileSystem> new_fs = nullptr;

                /* Try to open the existing fs. */
                FsFileSystem base_fs;
                bool opened_base_fs = false;
                if (with_id) {
                    opened_base_fs = R_SUCCEEDED(fsOpenFileSystemWithIdFwd(fwd, std::addressof(base_fs), static_cast<u64>(program_id), filesystem_type, path->str));
                } else {
                    opened_base_fs = R_SUCCEEDED(fsOpenFileSystemWithPatchFwd(fwd, std::addressof(base_fs), static_cast<u64>(program_id), filesystem_type));
                }

                if (opened_base_fs) {
                    /* Create a layered adapter. */
                    new_fs = std::make_shared<ReadOnlyLayeredFileSystem>(std::move(subdir_fs), std::make_unique<fs::RemoteFileSystem>(base_fs));
                } else {
                    /* Without an existing FS, just make a read only adapter to the subdirectory. */
                    new_fs = std::make_shared<fs::ReadOnlyFileSystem>(std::move(subdir_fs));
                }

                out.SetValue(MakeSharedFileSystem(std::move(new_fs), false), target_object_id);
            }

            R_SUCCEED();
        }

        Result OpenWebContentFileSystem(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> &out, ncm::ProgramId client_program_id, ncm::ProgramId program_id, FsFileSystemType filesystem_type, Service *fwd, const fssrv::sf::Path *path, bool with_id, bool try_program_specific) {
            /* Check first that we're a web applet opening web content. */
            R_UNLESS(ncm::IsWebAppletId(client_program_id),             sm::mitm::ResultShouldForwardToSession());
            R_UNLESS(filesystem_type == FsFileSystemType_ContentManual, sm::mitm::ResultShouldForwardToSession());

            /* Try to mount the HBL web filesystem. If this succeeds then we're done. */
            R_SUCCEED_IF(R_SUCCEEDED(OpenHblWebContentFileSystem(out, program_id)));

            /* If program specific override shouldn't be attempted, fall back. */
            R_UNLESS(try_program_specific, sm::mitm::ResultShouldForwardToSession());

            /* If we're not opening a HBL filesystem, just try to open a generic one. */
            R_RETURN(OpenProgramSpecificWebContentFileSystem(out, program_id, filesystem_type, fwd, path, with_id));
        }

    }
    
    Result OpenFileStorage(std::shared_ptr<fs::IStorage> *out, std::shared_ptr<fs::fsa::IFileSystem> &fs, const char *path) {
        /* Open the file storage. */
        std::shared_ptr<ams::fs::FileStorageBasedFileSystem> file_storage = fssystem::AllocateShared<ams::fs::FileStorageBasedFileSystem>();
        R_UNLESS(file_storage != nullptr, fs::ResultAllocationMemoryFailedInNcaFileSystemServiceImplB());

        /* Get the fs path. */
        ams::fs::Path fs_path;
        R_UNLESS(path != nullptr, fs::ResultNullptrArgument());
        R_TRY(fs_path.SetShallowBuffer(path));

        /* Initialize the file storage. */
        R_TRY(file_storage->Initialize(std::shared_ptr<fs::fsa::IFileSystem>(fs), fs_path, ams::fs::OpenMode_Read));

        /* Set the output. */
        *out = std::move(file_storage);
        R_SUCCEED();
    }

    Result CreateRootPartitionFileSystem(std::shared_ptr<fs::fsa::IFileSystem> *out, std::shared_ptr<fs::IStorage> &storage, const gc::impl::CardHeaderWithSignature &header) {
        /* Create meta data. */
        auto meta = std::make_unique<fssystem::Sha256PartitionFileSystemMeta>();
        AMS_ABORT_UNLESS(meta != nullptr);

        /* Initialize meta data. */
        {
            util::optional<u8> salt = util::nullopt;
            if (static_cast<fs::GameCardCompatibilityType>(header.data.encrypted_data.compatibility_type) != fs::GameCardCompatibilityType::Normal) {
                salt.emplace(header.data.encrypted_data.compatibility_type);
            }
            R_TRY(meta->Initialize(storage.get(), sf::GetNewDeleteMemoryResource(), header.data.partition_fs_header_hash, sizeof(header.data.partition_fs_header_hash), salt));
        }

        /* Create fs. */
        auto fs = std::make_shared<fssystem::Sha256PartitionFileSystem>();
        R_TRY(fs->Initialize(std::move(meta), storage));

        /* Set output. */
        *out = std::move(fs);
        R_SUCCEED();
    }

    Result CreatePartitionFileSystem(std::shared_ptr<fs::fsa::IFileSystem> *out, std::shared_ptr<fs::IStorage> &storage) {
            /* Create meta data. */
            auto meta = std::make_unique<fssystem::Sha256PartitionFileSystemMeta>();
            AMS_ABORT_UNLESS(meta != nullptr);

            s64 size;
            R_ABORT_UNLESS(storage->GetSize(std::addressof(size)));

            /* Initialize meta data. */
            R_TRY(meta->Initialize(storage.get(), sf::GetNewDeleteMemoryResource()));

            /* Create fs. */
            auto fs = std::make_shared<fssystem::Sha256PartitionFileSystem>();
            R_TRY(fs->Initialize(std::move(meta), storage));

            /* Set output. */
            *out = std::move(fs);
            R_SUCCEED();
        }

    Result FsMitmService::OpenGameCardStorage(sf::Out<sf::SharedPointer<ams::fssrv::sf::IStorage>> out, GameCardHandle handle, GameCardPartition partition) {
        if(HasSdFile("/game.xci")) {
            std::shared_ptr<fs::IStorage> key_area_storage;
            std::shared_ptr<fs::IStorage> body_storage;
            ams::fs::XciBodyHeader body_header;
            ams::fs::CardData card_data;

            ams::fs::PartitionData root_partition;
            ams::fs::PartitionData update_partition;
            ams::fs::PartitionData logo_partition;
            ams::fs::PartitionData normal_partition;
            ams::fs::PartitionData secure_partition;
            
            /* Mount the SD card using fs.mitm's session. */
            FsFileSystem sd_fs;
            std::shared_ptr<fs::IStorage> storage = nullptr;
            R_TRY(fsOpenSdCardFileSystem(std::addressof(sd_fs)));
            std::shared_ptr<fs::fsa::IFileSystem> sd_ifs = std::make_shared<fs::RemoteFileSystem>(sd_fs);

            if (const auto open_res = OpenFileStorage(std::addressof(storage), sd_ifs, "/game.xci"); R_SUCCEEDED(open_res)) {
                ams::fs::DetermineXciSubStorages(std::addressof(key_area_storage), std::addressof(body_storage), storage);
                R_ABORT_UNLESS(body_storage->Read(0, std::addressof(body_header), sizeof(body_header)));
                card_data.header = body_header.card_header;
                card_data.decrypted_header = card_data.header;
                R_ABORT_UNLESS(gc::impl::GcCrypto::DecryptCardHeader(std::addressof(card_data.decrypted_header.data), sizeof(card_data.decrypted_header.data)));

                /* Set up the headers for ca10 sign2. */
                if (card_data.header.data.flags & fs::GameCardAttribute_HasCa10CertificateFlag) {
                    card_data.ca10_certificate          = body_header.ca10_cert;
                    card_data.header_for_hash           = body_header.card_header_for_sign2;
                    card_data.decrypted_header_for_hash = card_data.header_for_hash;
                    R_ABORT_UNLESS(gc::impl::GcCrypto::DecryptCardHeader(std::addressof(card_data.decrypted_header_for_hash.data), sizeof(card_data.decrypted_header_for_hash.data)));
                } else {
                    card_data.ca10_certificate          = {};
                    card_data.header_for_hash           = card_data.header;
                    card_data.decrypted_header_for_hash = card_data.decrypted_header;
                }

                /* Read the T1 cert. */
                R_ABORT_UNLESS(body_storage->Read(CardPageSize * 0x38, std::addressof(card_data.t1_certificate), sizeof(card_data.t1_certificate)));

                /* Parse the root partition. */
                {
                    /* Create the root partition storage. */
                    using AlignmentMatchingStorageForGameCard = fssystem::AlignmentMatchingStorageInBulkRead<1>;
                    auto aligned_storage = std::make_shared<AlignmentMatchingStorageForGameCard>(body_storage, CardPageSize);

                    /* Get the size of the body. */
                    s64 body_size;
                    R_ABORT_UNLESS(aligned_storage->GetSize(std::addressof(body_size)));

                    /* Create sub storage for the root partition. */
                    root_partition.storage = std::make_shared<fs::SubStorage>(std::move(aligned_storage), card_data.header.data.partition_fs_header_address, body_size - card_data.header.data.partition_fs_header_address);

                    /* Create filesystem for the root partition. */
                    if (const auto res = CreateRootPartitionFileSystem(std::addressof(root_partition.fs), root_partition.storage, card_data.decrypted_header); R_FAILED(res)) {
                        fprintf(stderr, "[Warning]: Failed to mount the game card root partition: 2%03d-%04d\n", res.GetModule(), res.GetDescription());
                    }
                }

                /* Parse all other partitions. */
            if (root_partition.fs != nullptr) {
                const auto iter_result = fssystem::IterateDirectoryRecursively(root_partition.fs.get(),
                    fs::MakeConstantPath("/"),
                    [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                        R_SUCCEED();
                    },
                    [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                        R_SUCCEED();
                    },
                    [&] (const fs::Path &path, const fs::DirectoryEntry &) -> Result {
                        PartitionData *target_partition = nullptr;

                        if (std::strcmp(path.GetString(), "/update") == 0) {
                            target_partition = std::addressof(update_partition);
                        } else if (std::strcmp(path.GetString(), "/logo") == 0) {
                            target_partition = std::addressof(logo_partition);
                        } else if (std::strcmp(path.GetString(), "/normal") == 0) {
                            target_partition = std::addressof(normal_partition);
                        } else if (std::strcmp(path.GetString(), "/secure") == 0) {
                            target_partition = std::addressof(secure_partition);
                        } else {
                            fprintf(stderr, "[Warning]: Found unrecognized game card partition (%s)\n", path.GetString());
                        }

                        if (target_partition != nullptr) {
                            if (const auto res = OpenFileStorage(std::addressof(target_partition->storage), root_partition.fs, path.GetString()); R_SUCCEEDED(res)) {
                                if (const auto res = CreatePartitionFileSystem(std::addressof(target_partition->fs), target_partition->storage); R_FAILED(res)) {
                                    fprintf(stderr, "[Warning]: Failed to mount game card partition (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                                }
                            } else {
                                fprintf(stderr, "[Warning]: Failed to open game card partition (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                            }
                        }

                        R_SUCCEED();
                    }
                );
                if (R_FAILED(iter_result)) {
                    fprintf(stderr, "[Warning]: Iterating the root partition failed: 2%03d-%04d\n", iter_result.GetModule(), iter_result.GetDescription());
                }
            }

            FsStorage data_storage;
            const ::FsGameCardHandle _hnd = {handle};
            R_TRY(fsOpenGameCardStorage(&data_storage, &_hnd, static_cast<::FsGameCardPartition>(partition)));
            const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(&data_storage.s)};
            switch((u32)partition) {
                case 0:
                    out.SetValue(MakeSharedStorage(std::make_shared<ReadOnlyStorageAdapter>(std::move(update_partition.storage))), target_object_id);
                    return ResultSuccess();
                case 1:
                    out.SetValue(MakeSharedStorage(std::make_shared<ReadOnlyStorageAdapter>(std::move(normal_partition.storage))), target_object_id);
                    return ResultSuccess();
                case 2:
                    out.SetValue(MakeSharedStorage(std::make_shared<ReadOnlyStorageAdapter>(std::move(secure_partition.storage))), target_object_id);
                    return ResultSuccess();
                case 3:
                    out.SetValue(MakeSharedStorage(std::make_shared<ReadOnlyStorageAdapter>(std::move(logo_partition.storage))), target_object_id);
                    return ResultSuccess();
            }

            }
        } else {
            FsStorage data_storage;
            const ::FsGameCardHandle _hnd = {handle};
            R_TRY(fsOpenGameCardStorage(&data_storage, &_hnd, static_cast<::FsGameCardPartition>(partition)));
            const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(&data_storage.s)};
            std::unique_ptr<ams::fs::IStorage> unique_bis = std::make_unique<RemoteStorage>(data_storage);
            out.SetValue(MakeSharedStorage(std::make_shared<ReadOnlyStorageAdapter>(std::move(unique_bis))), target_object_id);
            return ResultSuccess();
        }
        return ResultSuccess();
        /**/
    }

    Result FsMitmService::OpenGameCardFileSystem(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> out, ams::fs::GameCardHandle handle, ams::fs::GameCardPartition partition) {
        /* Mount the SD card using fs.mitm's session. */
        if(HasSdFile("/game.xci")) {
            std::shared_ptr<fs::IStorage> key_area_storage;
            std::shared_ptr<fs::IStorage> body_storage;
            ams::fs::XciBodyHeader body_header;
            ams::fs::CardData card_data;

            ams::fs::PartitionData root_partition;
            ams::fs::PartitionData update_partition;
            ams::fs::PartitionData logo_partition;
            ams::fs::PartitionData normal_partition;
            ams::fs::PartitionData secure_partition;

            FsFileSystem sd_fs;
            std::shared_ptr<fs::IStorage> storage = nullptr;
            R_TRY(fsOpenSdCardFileSystem(std::addressof(sd_fs)));
            std::shared_ptr<fs::fsa::IFileSystem> sd_ifs = std::make_shared<fs::RemoteFileSystem>(sd_fs);

            if (const auto open_res = OpenFileStorage(std::addressof(storage), sd_ifs, "/game.xci"); R_SUCCEEDED(open_res)) {
                ams::fs::DetermineXciSubStorages(std::addressof(key_area_storage), std::addressof(body_storage), storage);
                R_ABORT_UNLESS(body_storage->Read(0, std::addressof(body_header), sizeof(body_header)));
                card_data.header = body_header.card_header;
                card_data.decrypted_header = card_data.header;
                R_ABORT_UNLESS(gc::impl::GcCrypto::DecryptCardHeader(std::addressof(card_data.decrypted_header.data), sizeof(card_data.decrypted_header.data)));

                /* Set up the headers for ca10 sign2. */
                if (card_data.header.data.flags & fs::GameCardAttribute_HasCa10CertificateFlag) {
                    card_data.ca10_certificate          = body_header.ca10_cert;
                    card_data.header_for_hash           = body_header.card_header_for_sign2;
                    card_data.decrypted_header_for_hash = card_data.header_for_hash;
                    R_ABORT_UNLESS(gc::impl::GcCrypto::DecryptCardHeader(std::addressof(card_data.decrypted_header_for_hash.data), sizeof(card_data.decrypted_header_for_hash.data)));
                } else {
                    card_data.ca10_certificate          = {};
                    card_data.header_for_hash           = card_data.header;
                    card_data.decrypted_header_for_hash = card_data.decrypted_header;
                }

                /* Read the T1 cert. */
                R_ABORT_UNLESS(body_storage->Read(CardPageSize * 0x38, std::addressof(card_data.t1_certificate), sizeof(card_data.t1_certificate)));

                /* Parse the root partition. */
                {
                    /* Create the root partition storage. */
                    using AlignmentMatchingStorageForGameCard = fssystem::AlignmentMatchingStorageInBulkRead<1>;
                    auto aligned_storage = std::make_shared<AlignmentMatchingStorageForGameCard>(body_storage, CardPageSize);

                    /* Get the size of the body. */
                    s64 body_size;
                    R_ABORT_UNLESS(aligned_storage->GetSize(std::addressof(body_size)));

                    /* Create sub storage for the root partition. */
                    root_partition.storage = std::make_shared<fs::SubStorage>(std::move(aligned_storage), card_data.header.data.partition_fs_header_address, body_size - card_data.header.data.partition_fs_header_address);

                    /* Create filesystem for the root partition. */
                    if (const auto res = CreateRootPartitionFileSystem(std::addressof(root_partition.fs), root_partition.storage, card_data.decrypted_header); R_FAILED(res)) {
                        fprintf(stderr, "[Warning]: Failed to mount the game card root partition: 2%03d-%04d\n", res.GetModule(), res.GetDescription());
                    }
                }

                /* Parse all other partitions. */
            if (root_partition.fs != nullptr) {
                const auto iter_result = fssystem::IterateDirectoryRecursively(root_partition.fs.get(),
                    fs::MakeConstantPath("/"),
                    [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                        R_SUCCEED();
                    },
                    [&] (const fs::Path &, const fs::DirectoryEntry &) -> Result {
                        R_SUCCEED();
                    },
                    [&] (const fs::Path &path, const fs::DirectoryEntry &) -> Result {
                        PartitionData *target_partition = nullptr;

                        if (std::strcmp(path.GetString(), "/update") == 0) {
                            target_partition = std::addressof(update_partition);
                        } else if (std::strcmp(path.GetString(), "/logo") == 0) {
                            target_partition = std::addressof(logo_partition);
                        } else if (std::strcmp(path.GetString(), "/normal") == 0) {
                            target_partition = std::addressof(normal_partition);
                        } else if (std::strcmp(path.GetString(), "/secure") == 0) {
                            target_partition = std::addressof(secure_partition);
                        } else {
                            fprintf(stderr, "[Warning]: Found unrecognized game card partition (%s)\n", path.GetString());
                        }

                        if (target_partition != nullptr) {
                            if (const auto res = OpenFileStorage(std::addressof(target_partition->storage), root_partition.fs, path.GetString()); R_SUCCEEDED(res)) {
                                if (const auto res = CreatePartitionFileSystem(std::addressof(target_partition->fs), target_partition->storage); R_FAILED(res)) {
                                    fprintf(stderr, "[Warning]: Failed to mount game card partition (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                                }
                            } else {
                                fprintf(stderr, "[Warning]: Failed to open game card partition (%s): 2%03d-%04d\n", path.GetString(), res.GetModule(), res.GetDescription());
                            }
                        }

                        R_SUCCEED();
                    }
                );
                if (R_FAILED(iter_result)) {
                    fprintf(stderr, "[Warning]: Iterating the root partition failed: 2%03d-%04d\n", iter_result.GetModule(), iter_result.GetDescription());
                }
            }

            FsFileSystem base_fs;
            const ::FsGameCardHandle _hnd = {handle};
            R_TRY(m_fsOpenGameCardFileSystem(m_forward_service.get(), &base_fs, &_hnd, static_cast<::FsGameCardPartition>(partition)));
            const sf::cmif::DomainObjectId target_object_id1{serviceGetObjectId(&base_fs.s)};
            std::shared_ptr<fs::fsa::IFileSystem> redir_fs = nullptr;

            switch((u32)partition) {
                case 0:
                    redir_fs = update_partition.fs;
                    out.SetValue(MakeSharedFileSystem(std::move(redir_fs), false), target_object_id1);
                    return ResultSuccess();
                case 1:
                    redir_fs = normal_partition.fs;
                    out.SetValue(MakeSharedFileSystem(std::move(redir_fs), false), target_object_id1);
                    return ResultSuccess();
                case 2:
                    redir_fs = secure_partition.fs;
                    out.SetValue(MakeSharedFileSystem(std::move(redir_fs), false), target_object_id1);
                    return ResultSuccess();
                case 3:
                    redir_fs = logo_partition.fs;
                    out.SetValue(MakeSharedFileSystem(std::move(redir_fs), false), target_object_id1);
                    return ResultSuccess();
            }

            }
        } else {
            FsFileSystem base_fs;
            const ::FsGameCardHandle _hnd = {handle};
            R_TRY(m_fsOpenGameCardFileSystem(m_forward_service.get(), &base_fs, &_hnd, static_cast<::FsGameCardPartition>(partition)));
            const sf::cmif::DomainObjectId target_object_id1{serviceGetObjectId(&base_fs.s)};
            std::shared_ptr<fs::fsa::IFileSystem> redir_fs =  std::make_unique<RemoteFileSystem>(base_fs);
            out.SetValue(MakeSharedFileSystem(std::move(redir_fs), false), target_object_id1);
            return ResultSuccess();
        }
        return ResultSuccess();
    }

    Result FsMitmService::OpenFileSystemWithPatch(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> out, ncm::ProgramId program_id, u32 _filesystem_type) {
        R_RETURN(OpenWebContentFileSystem(out, m_client_info.program_id, program_id, static_cast<FsFileSystemType>(_filesystem_type), m_forward_service.get(), nullptr, false, m_client_info.override_status.IsProgramSpecific()));
    }

    Result FsMitmService::OpenFileSystemWithId(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> out, const fssrv::sf::Path &path, ncm::ProgramId program_id, u32 _filesystem_type) {
        R_RETURN(OpenWebContentFileSystem(out, m_client_info.program_id, program_id, static_cast<FsFileSystemType>(_filesystem_type), m_forward_service.get(), std::addressof(path), true, m_client_info.override_status.IsProgramSpecific()));
    }

    Result FsMitmService::OpenSdCardFileSystem(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> out) {
        /* We only care about redirecting this for NS/emummc. */
        R_UNLESS(m_client_info.program_id == ncm::SystemProgramId::Ns, sm::mitm::ResultShouldForwardToSession());
        R_UNLESS(emummc::IsActive(),                                   sm::mitm::ResultShouldForwardToSession());

        /* Create a new SD card filesystem. */
        FsFileSystem sd_fs;
        R_TRY(fsOpenSdCardFileSystemFwd(m_forward_service.get(), std::addressof(sd_fs)));
        const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(sd_fs.s))};

        /* Return output filesystem. */
        auto redir_fs = std::make_shared<fssystem::DirectoryRedirectionFileSystem>(std::make_unique<RemoteFileSystem>(sd_fs));
        R_TRY(redir_fs->InitializeWithFixedPath("/Nintendo", emummc::GetNintendoDirPath()));

        out.SetValue(MakeSharedFileSystem(std::move(redir_fs), false), target_object_id);
        R_SUCCEED();
    }

    Result FsMitmService::OpenSaveDataFileSystem(sf::Out<sf::SharedPointer<ams::fssrv::sf::IFileSystem>> out, u8 _space_id, const fs::SaveDataAttribute &attribute) {
        /* We only want to intercept saves for games, right now. */
        const bool is_game_or_hbl = m_client_info.override_status.IsHbl() || ncm::IsApplicationId(m_client_info.program_id);
        R_UNLESS(is_game_or_hbl, sm::mitm::ResultShouldForwardToSession());

        /* Only redirect if the appropriate system setting is set. */
        R_UNLESS(GetSettingsItemBooleanValue("atmosphere", "fsmitm_redirect_saves_to_sd"), sm::mitm::ResultShouldForwardToSession());

        /* Only redirect if the specific title being accessed has a redirect save flag. */
        R_UNLESS(cfg::HasContentSpecificFlag(m_client_info.program_id, "redirect_save"), sm::mitm::ResultShouldForwardToSession());

        /* Only redirect account savedata. */
        R_UNLESS(attribute.type == fs::SaveDataType::Account, sm::mitm::ResultShouldForwardToSession());

        /* Get enum type for space id. */
        auto space_id = static_cast<FsSaveDataSpaceId>(_space_id);

        /* Verify we can open the save. */
        static_assert(sizeof(fs::SaveDataAttribute) == sizeof(::FsSaveDataAttribute));
        FsFileSystem save_fs;
        R_UNLESS(R_SUCCEEDED(fsOpenSaveDataFileSystemFwd(m_forward_service.get(), std::addressof(save_fs), space_id, reinterpret_cast<const FsSaveDataAttribute *>(std::addressof(attribute)))), sm::mitm::ResultShouldForwardToSession());
        std::unique_ptr<fs::fsa::IFileSystem> save_ifs = std::make_unique<fs::RemoteFileSystem>(save_fs);

        /* Mount the SD card using fs.mitm's session. */
        FsFileSystem sd_fs;
        R_TRY(fsOpenSdCardFileSystem(std::addressof(sd_fs)));
        const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(sd_fs.s))};
        std::shared_ptr<fs::fsa::IFileSystem> sd_ifs = std::make_shared<fs::RemoteFileSystem>(sd_fs);

        /* Verify that we can open the save directory, and that it exists. */
        const ncm::ProgramId application_id = attribute.program_id == ncm::InvalidProgramId ? m_client_info.program_id : attribute.program_id;

        char save_dir_raw_path[0x100];
        R_TRY(mitm::fs::SaveUtil::GetDirectorySaveDataPath(save_dir_raw_path, sizeof(save_dir_raw_path), application_id, space_id, attribute));

        ams::fs::Path save_dir_path;
        R_TRY(save_dir_path.SetShallowBuffer(save_dir_raw_path));

        /* Check if this is the first time we're making the save. */
        bool is_new_save = false;
        {
            fs::DirectoryEntryType ent;
            R_TRY_CATCH(sd_ifs->GetEntryType(std::addressof(ent), save_dir_path)) {
                R_CATCH(fs::ResultPathNotFound) { is_new_save = true; }
                R_CATCH_ALL() { /* ... */ }
            } R_END_TRY_CATCH;
        }

        /* Ensure the directory exists. */
        R_TRY(fssystem::EnsureDirectory(sd_ifs.get(), save_dir_path));

        /* Create directory savedata filesystem. */
        auto subdir_fs = std::make_unique<fssystem::SubDirectoryFileSystem>(sd_ifs);
        R_TRY(subdir_fs->Initialize(save_dir_path));

        std::shared_ptr<fssystem::DirectorySaveDataFileSystem> dirsave_ifs = std::make_shared<fssystem::DirectorySaveDataFileSystem>(std::move(subdir_fs));

        /* Ensure correct directory savedata filesystem state. */
        R_TRY(dirsave_ifs->Initialize(true, true, true));

        /* If it's the first time we're making the save, copy existing savedata over. */
        if (is_new_save) {
            /* TODO: Check error? */
            fs::DirectoryEntry work_entry;
            constexpr const fs::Path root_path = fs::MakeConstantPath("/");

            u8 savedata_copy_buffer[2_KB];
            fssystem::CopyDirectoryRecursively(dirsave_ifs.get(), save_ifs.get(), root_path, root_path, std::addressof(work_entry), savedata_copy_buffer, sizeof(savedata_copy_buffer));
        }

        /* Set output. */
        out.SetValue(MakeSharedFileSystem(std::move(dirsave_ifs), false), target_object_id);
        R_SUCCEED();
    }

    Result FsMitmService::OpenBisStorage(sf::Out<sf::SharedPointer<ams::fssrv::sf::IStorage>> out, u32 _bis_partition_id) {
        const ::FsBisPartitionId bis_partition_id = static_cast<::FsBisPartitionId>(_bis_partition_id);

        /* Try to open a storage for the partition. */
        FsStorage bis_storage;
        R_TRY(fsOpenBisStorageFwd(m_forward_service.get(), std::addressof(bis_storage), bis_partition_id));
        const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(bis_storage.s))};

        const bool is_sysmodule = ncm::IsSystemProgramId(m_client_info.program_id);
        const bool is_hbl = m_client_info.override_status.IsHbl();
        const bool can_write_bis = is_sysmodule || (is_hbl && GetSettingsItemBooleanValue("atmosphere", "enable_hbl_bis_write"));

        /* Allow HBL to write to boot1 (safe firm) + package2. */
        /* This is needed to not break compatibility with ChoiDujourNX, which does not check for write access before beginning an update. */
        /* TODO: get fixed so that this can be turned off without causing bricks :/ */
        const bool is_package2 = (FsBisPartitionId_BootConfigAndPackage2Part1 <= bis_partition_id && bis_partition_id <= FsBisPartitionId_BootConfigAndPackage2Part6);
        const bool is_boot1    = bis_partition_id == FsBisPartitionId_BootPartition2Root;
        const bool can_write_bis_for_choi_support = is_hbl && (is_package2 || is_boot1);

        /* Set output storage. */
        if (bis_partition_id == FsBisPartitionId_BootPartition1Root) {
            if (IsBoot0CustomPublicKey(bis_storage)) {
                out.SetValue(MakeSharedStorage(std::make_shared<CustomPublicKeyBoot0Storage>(bis_storage, m_client_info, spl::GetSocType())), target_object_id);
            } else {
                out.SetValue(MakeSharedStorage(std::make_shared<Boot0Storage>(bis_storage, m_client_info)), target_object_id);
            }
        } else if (bis_partition_id == FsBisPartitionId_CalibrationBinary) {
            out.SetValue(MakeSharedStorage(std::make_shared<CalibrationBinaryStorage>(bis_storage, m_client_info)), target_object_id);
        } else {
            if (can_write_bis || can_write_bis_for_choi_support) {
                /* We can write, so create a writable storage. */
                out.SetValue(MakeSharedStorage(std::make_shared<RemoteStorage>(bis_storage)), target_object_id);
            } else {
                /* We can only read, so create a readable storage. */
                std::unique_ptr<ams::fs::IStorage> unique_bis = std::make_unique<RemoteStorage>(bis_storage);
                out.SetValue(MakeSharedStorage(std::make_shared<ReadOnlyStorageAdapter>(std::move(unique_bis))), target_object_id);
            }
        }

        R_SUCCEED();
    }

    Result FsMitmService::OpenDataStorageByCurrentProcess(sf::Out<sf::SharedPointer<ams::fssrv::sf::IStorage>> out) {
        /* Only mitm if we should override contents for the current process. */
        R_UNLESS(m_client_info.override_status.IsProgramSpecific(),     sm::mitm::ResultShouldForwardToSession());

        /* Only mitm if there is actually an override romfs. */
        R_UNLESS(mitm::fs::HasSdRomfsContent(m_client_info.program_id), sm::mitm::ResultShouldForwardToSession());

        /* Try to open the process romfs. */
        FsStorage data_storage;
        R_TRY(fsOpenDataStorageByCurrentProcessFwd(m_forward_service.get(), std::addressof(data_storage)));
        const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(data_storage.s))};

        /* Get a layered storage for the process romfs. */
        out.SetValue(MakeSharedStorage(GetLayeredRomfsStorage(m_client_info.program_id, data_storage, true)), target_object_id);
        R_SUCCEED();
    }

    Result FsMitmService::OpenDataStorageByDataId(sf::Out<sf::SharedPointer<ams::fssrv::sf::IStorage>> out, ncm::DataId _data_id, u8 storage_id) {
        /* Only mitm if we should override contents for the current process. */
        R_UNLESS(m_client_info.override_status.IsProgramSpecific(), sm::mitm::ResultShouldForwardToSession());

        /* TODO: Decide how to handle DataId vs ProgramId for this API. */
        const ncm::ProgramId data_id = {_data_id.value};

        /* Only mitm if there is actually an override romfs. */
        R_UNLESS(mitm::fs::HasSdRomfsContent(data_id),                  sm::mitm::ResultShouldForwardToSession());

        /* Try to open the data id. */
        FsStorage data_storage;
        R_TRY(fsOpenDataStorageByDataIdFwd(m_forward_service.get(), std::addressof(data_storage), static_cast<u64>(data_id), static_cast<NcmStorageId>(storage_id)));
        const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(data_storage.s))};

        /* Get a layered storage for the data id. */
        out.SetValue(MakeSharedStorage(GetLayeredRomfsStorage(data_id, data_storage, false)), target_object_id);
        R_SUCCEED();
    }

    Result FsMitmService::OpenDataStorageWithProgramIndex(sf::Out<sf::SharedPointer<ams::fssrv::sf::IStorage>> out, u8 program_index) {
        /* Only mitm if we should override contents for the current process. */
        R_UNLESS(m_client_info.override_status.IsProgramSpecific(), sm::mitm::ResultShouldForwardToSession());

        /* Get the relevant program id. */
        const ncm::ProgramId program_id = g_program_index_map_info_manager.GetProgramId(m_client_info.program_id, program_index);

        /* If we don't know about the program or don't have content, forward. */
        R_UNLESS(program_id != ncm::InvalidProgramId,     sm::mitm::ResultShouldForwardToSession());
        R_UNLESS(mitm::fs::HasSdRomfsContent(program_id), sm::mitm::ResultShouldForwardToSession());

        /* Try to open the process romfs. */
        FsStorage data_storage;
        R_TRY(fsOpenDataStorageWithProgramIndexFwd(m_forward_service.get(), std::addressof(data_storage), program_index));
        const sf::cmif::DomainObjectId target_object_id{serviceGetObjectId(std::addressof(data_storage.s))};

        /* Get a layered storage for the process romfs. */
        out.SetValue(MakeSharedStorage(GetLayeredRomfsStorage(program_id, data_storage, true)), target_object_id);
        R_SUCCEED();
    }

    Result FsMitmService::RegisterProgramIndexMapInfo(const sf::InBuffer &info_buffer, s32 info_count) {
        /* Try to register with FS. */
        R_TRY(fsRegisterProgramIndexMapInfoFwd(m_forward_service.get(), info_buffer.GetPointer(), info_buffer.GetSize(), info_count));

        /* Register with ourselves. */
        R_ABORT_UNLESS(g_program_index_map_info_manager.Reset(reinterpret_cast<const fs::ProgramIndexMapInfo *>(info_buffer.GetPointer()), info_count));

        R_SUCCEED();
    }

}
