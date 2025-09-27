// https://github.com/PS5Dev/Byepervisor/blob/57204cbd7bd26ed4623634d52b0f60f40d630087/hen/src/fpkg.cpp#L82

#include <string.h>
#include "utils.h"
#include "npdrm.h"
#include "log.h"
#include "fpu.h"

#include "../libtomcrypt/src/headers/tomcrypt.h"

// #define NPDRM_PORTING 1

#ifndef NPDRM_PORTING
extern char sceSblServiceMailbox_lr_npdrm_cmd_5[];
extern char sceSblServiceMailbox_lr_npdrm_cmd_6[];
#endif
extern char sceSblServiceMailbox[];

static const uint8_t rif_debug_key[] = {0x96, 0xC2, 0x26, 0x8D, 0x69, 0x26, 0x1C, 0x8B, 0x1E, 0x3B, 0x6B, 0xFF, 0x2F, 0xE0, 0x4E, 0x12};

int aes_cbc_128_decrypt(uint8_t *out, const uint8_t *in, int size, const uint8_t *key, const uint8_t *iv)
{
    int err = -1;
    static int aes_cipher = -1;
    uelf_fpu_enter();
    if (aes_cipher < 0)
    {
        if ((aes_cipher = register_cipher(&aes_desc)) < 0) goto exit;
    }

    symmetric_CBC cbc;
    if ((err = cbc_start(aes_cipher, iv, key, 16, 0, &cbc)) != CRYPT_OK) goto exit;
    if ((err = cbc_decrypt(in, out, size, &cbc)) != CRYPT_OK) goto exit;
    if ((err = cbc_done(&cbc)) != CRYPT_OK) goto exit;
exit:
    uelf_fpu_exit();
    return err;
}

int sha256_buffer(const unsigned char *in, unsigned long inlen, unsigned char *out)
{
    hash_state md;
    int err = -1;

    uelf_fpu_enter();
    if ((err = sha256_init(&md)) != CRYPT_OK) goto exit;
    if ((err = sha256_process(&md, in, inlen)) != CRYPT_OK) goto exit;
    if ((err = sha256_done(&md, out)) != CRYPT_OK) goto exit;
exit:
    uelf_fpu_exit();
    return err;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *p1 = (const unsigned char *)s1;
    const unsigned char *p2 = (const unsigned char *)s2;
    for (size_t i = 0; i < n; i++)
    {
        if (p1[i] != p2[i])
        {
            return (int)p1[i] - (int)p2[i];
        }
    }
    return 0;
}

int try_handle_npdrm_mailbox(uint64_t *regs, uint64_t lr)
{
#ifndef NPDRM_PORTING
    if (lr != (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_5 &&
        lr != (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_6)
    {
        return 0;
    }
#else
    uint32_t cmd;
    if (copy_from_kernel(&cmd, regs[RDX], sizeof(cmd)))
    {
        return 0;
    }
    // Other functions may use this same cmd number for different purposes (depending on RDI/handle i believe, however its value changes between fws)
    // for example, sceSblServiceMailbox_lr_decryptSelfBlock also sees cmd 6
    // if we only relied on this, it would work safely because of the later checks, its just wasteful
    if (cmd != 5 && cmd != 6)
    {
        return 0;
    }
#endif

    uint64_t rif_pa = kpeek64(regs[RDX] + 0x8);

    struct RifCmd56MemoryLayout layout;
    memcpy(&layout, DMEM + rif_pa, sizeof(layout));

    if (layout.rif.type != 0x2)
    {
#ifdef NPDRM_PORTING
        return 0;
#else
        return 1;
#endif
    }

    uint8_t contentid_hash[32];
    if (sha256_buffer(layout.rif.contentId, sizeof(layout.rif.contentId), contentid_hash))
    {
#ifdef NPDRM_PORTING
        return 0;
#else
        return 1;
#endif
    }

    if (memcmp(contentid_hash, layout.rif.rifIv, 16) != 0)
    {
#ifdef NPDRM_PORTING
        return 0;
#else
        // not a debug rif
        return 1;
#endif
    }

#ifdef NPDRM_PORTING
    // Now that we know the input data is a (debug) rif, we know we are at the right place
    log_word(0x10C7100000000001UL + (cmd << 16));
    log_word(lr);
#endif

    layout.output.version = __builtin_bswap16(layout.rif.version);
    layout.output.unk04 = __builtin_bswap16(layout.rif.unk06);
    layout.output.psnid = __builtin_bswap64(layout.rif.psnid);
    layout.output.startTimestamp = __builtin_bswap64(layout.rif.startTimestamp);
    layout.output.endTimestamp = __builtin_bswap64(layout.rif.endTimestamp);
    layout.output.extraFlags = __builtin_bswap64(layout.rif.extraFlags);
    layout.output.type = __builtin_bswap16(layout.rif.type);
    layout.output.contentType = __builtin_bswap16(layout.rif.contentType);
    layout.output.skuFlag = __builtin_bswap16(layout.rif.skuFlag);
    layout.output.unk34 = __builtin_bswap32(layout.rif.unk60);
    layout.output.unk38 = __builtin_bswap32(layout.rif.unk64);
    layout.output.unk3C = 0;
    layout.output.unk40 = 0;
    layout.output.unk44 = 0;
    memcpy(layout.output.contentId, layout.rif.contentId, 0x30);
    memcpy(layout.output.rifIv, layout.rif.rifIv, 0x10);
    layout.output.unk88 = __builtin_bswap32(layout.rif.unk70);
    layout.output.unk8C = __builtin_bswap32(layout.rif.unk74);
    layout.output.unk90 = __builtin_bswap32(layout.rif.unk78);
    layout.output.unk94 = __builtin_bswap32(layout.rif.unk7C);
    memcpy(layout.output.unk98, layout.rif.unk80, 0x10);
    if (layout.output.skuFlag == 2)
    {
        layout.output.skuFlag = 1;
    }

#ifdef NPDRM_PORTING
    if (cmd == 6)
#else
    if (lr == (uint64_t)sceSblServiceMailbox_lr_npdrm_cmd_6)
#endif
    {
        uint8_t decrypted_secret[sizeof(layout.rif.rifSecret)];
        if (aes_cbc_128_decrypt(decrypted_secret, layout.rif.rifSecret, sizeof(layout.rif.rifSecret), rif_debug_key, layout.rif.rifIv))
        {
            return 1;
        }

        if (memcmp(contentid_hash + 16, decrypted_secret, 16) != 0)
        {
            // does not use debug rif key/failed to decrypt?
            return 1;
        }

        // copy both unk10 and unk20
        copy_to_kernel(regs[RDX] + __builtin_offsetof(struct NpDrmCmd6, unk10), &decrypted_secret[0x70], 0x20);
    }

    memcpy(DMEM + rif_pa + __builtin_offsetof(struct RifCmd56MemoryLayout, output), &layout.output, sizeof(layout.output));

    uint32_t res = 0;
    copy_to_kernel(regs[RDX] + 0x4, &res, sizeof(res));

    regs[RIP] = lr;
    regs[RAX] = 0;
    regs[RSP] += 8;
    return 1;
}

static const uint64_t dbgregs_for_ioctl[6] = {
    (uint64_t)sceSblServiceMailbox, 0, 0, 0,
    0, 0x401};

void handle_ioctl_syscall(uint64_t *regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_ioctl);
}