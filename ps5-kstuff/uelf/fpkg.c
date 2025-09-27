#include <string.h>
#include <errno.h>
#include "fpkg.h"
#include "utils.h"
#include "traps.h"
#include "log.h"
#include "pfs_crypto.h"
#include "fakekeys.h"

extern char sceSblServiceMailbox[];
extern char sceSblServiceMailbox_lr_verifySuperBlock[];
extern char sceSblServiceMailbox_lr_sceSblPfsClearKey_1[];
extern char sceSblServiceMailbox_lr_sceSblPfsClearKey_2[];
extern char sceSblServiceCryptAsync_deref_singleton[];
extern char crypt_message_resolve[];
extern char doreti_iret[];

#define IDX_TO_HANDLE(x) (0x13374100 | ((uint8_t)((x)+1)))
#define HANDLE_TO_IDX(x) ((((x) & 0xffffff00) == 0x13374100 ? ((int)(uint8_t)(x)) : (int)0) - 1)

static void crypto_request_emulated(uint64_t* regs, uint64_t msg, uint32_t status)
{
    uint64_t frame[7] = {
        (uint64_t)doreti_iret,
        MKTRAP(TRAP_FPKG, 1), 0, 0, 0, 0,
        0
    };
    push_stack(regs, frame, sizeof(frame));
    regs[RIP] = (uint64_t)crypt_message_resolve;
    regs[RDI] = msg;
    regs[RSI] = status;
}

static int handle_crypto_message(uint64_t* regs, uint64_t msg, uint64_t bytes_cap, uint64_t* bytes_handled)
{
    uint64_t msg_data[21];
    copy_from_kernel(msg_data, msg, sizeof(msg_data));
    if((msg_data[0] & 0x7fffffff) == 0x9132000) // SHA256HMAC with key handle
    {
        int idx = HANDLE_TO_IDX(msg_data[20]);
        //log_word(0xfee10006dead0000|(uint16_t)idx);
        if(idx < 0)
            return ENOSYS;
        uint8_t key[32];
        if(!get_fake_key(idx, key))
            return ENOSYS;
        if(msg_data[3] != msg_data[1] * 8)
            return ENOSYS;
        //log_word(0xdead0006dead0007);
        uint8_t hash[32] = {0};
        *bytes_handled += msg_data[1];
        if(bytes_cap < *bytes_handled && pfs_hmac_virtual(hash, key, msg_data[2], msg_data[1]))
		 
										   
            return -1;
		 
        copy_to_kernel(msg+32, hash, 32);
        return 0;
    }
    else if((msg_data[0] & 0x7ffff7ff) == 0x2108000) // AES-XTS decrypt/encrypt with key handle
    {
        int idx = HANDLE_TO_IDX(msg_data[5]);
        //log_word(0xfee10006dead0100|(uint16_t)idx|((msg_data[0]&0x800)<<4));
        if(idx < 0)
            return ENOSYS;
        uint8_t key[32];
        if(!get_fake_key(idx, key))
            return ENOSYS;
        //log_word(0xdead0006dead0007);
        uint64_t n_sectors = (uint32_t)msg_data[1];
        uint64_t offset = (bytes_cap - *bytes_handled) >> 12;
        if(offset >= n_sectors)
        {
            *bytes_handled += n_sectors << 12;
            return 0;
        }
        *bytes_handled = bytes_cap + 4096;
        if(pfs_xts_virtual(msg_data[3] + (offset << 12), msg_data[2] + (offset << 12), key, msg_data[4] + offset, 1, (msg_data[0] & 0x800) >> 11))
        {
            //log_word(0xfee1fee1fee1fee1);
            return -1;
        }
        else
            return (offset == n_sectors - 1) ? 0 : EINTR;
    }
    //log_word(0xdead0006dead0006);
    //log_word(msg);
    /*for(int i = 0; i < 32; i++)
        log_word(msg_data[i]);*/
    //log_word(0xdead0006ffffffff);
    return ENOSYS;
}

static inline uint64_t rdtsc(void)
{
    uint32_t a, d;
    asm volatile("rdtsc":"=a"(a),"=d"(d));
    return (uint64_t)d << 32 | a;
}

static int handle_crypto_request(uint64_t* regs, uint64_t bytes_handled)
{
    uint64_t start_time = rdtsc();
    int total = 0;
    int emulated = 0;
    int total_status = 0;
    uint64_t new_bytes_handled = 0;

    uint64_t start = (fwver >= 0x800) ? regs[RBX] : regs[R14];

    for (uint64_t msg = start; msg && !total_status; msg = kpeek64(msg + 320))
    {
        int status = handle_crypto_message(regs, msg, bytes_handled, &new_bytes_handled);

        if (status == EINTR) // partial decrypt, need to restart the syscall
        {
            uint64_t frame[6] = {
                MKTRAP(TRAP_FPKG, 2), 0, 0, 0, 0,
                new_bytes_handled,
            };
            push_stack(regs, frame, sizeof(frame));
            regs[RIP] = (uint64_t)doreti_iret;
            return 1;
        }

        total++;

        if (status != ENOSYS)
        {
            emulated++;
            if (status)
                total_status = status;
        }
    }

    if (emulated)
    {
        if (emulated < total)
        {
            // not all requests successfully emulated
            // we can't run only part of the request, so just report failure
            total_status = -1;
        }

        crypto_request_emulated(regs, (fwver >= 0x800) ? regs[RBX] : regs[R14], total_status);

        uint64_t end_time = rdtsc();
        /*log_word(0x1234);
        log_word(end_time - start_time);*/
        return 1;
    }

    return 0;
}

int try_handle_fpkg_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)sceSblServiceCryptAsync_deref_singleton)
    {
        if(!handle_crypto_request(regs, 0))
        {
            regs[RAX] |= -1ull << 48;
            regs[RBX] |= -1ull << 48;
        }
    }
    else
        return 0;
    return 1;
}

int try_handle_fpkg_mailbox(uint64_t* regs, uint64_t lr)
{
    if(lr == (uint64_t)sceSblServiceMailbox_lr_verifySuperBlock)
    {
        uint64_t req[8];
        copy_from_kernel(req, regs[RDX], 64);
        uint64_t p_eekpfs = 0;
        memcpy(&p_eekpfs, DMEM+req[2]+32, 8);
        uint8_t eekpfs[256] = {0};
        memcpy(eekpfs, DMEM+p_eekpfs, 256);
        uint8_t crypt_seed[16];
        memcpy(crypt_seed, DMEM+req[3]+0x370, 16);
        uint8_t ek[32] = {}, sk[32] = {};
        if(pfs_derive_fake_keys(eekpfs, crypt_seed, ek, sk))
        {
            int key1 = register_fake_key(ek);
            if(key1 >= 0)
            {
                int key2 = register_fake_key(sk);
                if(key2 >= 0)
                {
                    regs[RIP] = lr;
                    regs[RAX] = 0;
                    regs[RSP] += 8;
                    uint32_t fake_resp[4] = {0, 0, IDX_TO_HANDLE(key1), IDX_TO_HANDLE(key2)};
                    copy_to_kernel(regs[RDX], fake_resp, sizeof(fake_resp));
                }
            }
        }
    }
    else if(lr == (uint64_t)sceSblServiceMailbox_lr_sceSblPfsClearKey_1
         || lr == (uint64_t)sceSblServiceMailbox_lr_sceSblPfsClearKey_2)
    {
        uint32_t handle = kpeek64(regs[RDX]+8);

        int key = HANDLE_TO_IDX(handle);
        if(key >= 0 && unregister_fake_key(key))
        {
            copy_to_kernel(regs[RDX], (const uint64_t[16]){}, 16);

            regs[RIP] = lr;
            regs[RAX] = 0;
            regs[RSP] += 8;
        }
    }
    /*else
    {
        uint64_t req[2];
        copy_from_kernel(req, regs[RDX], sizeof(req));
        if((uint32_t)req[0] == 3)
        {
            log_word(0x4141414141414141);
            log_word(req[0]);
            log_word(req[1]);
            int key = HANDLE_TO_IDX(req[1]);
            log_word(key);
            if(key >= 0 && unregister_fake_key(key))
            {
                log_word(0x4141414141414142);
                log_word(lr);
                copy_to_kernel(regs[RDX], (const uint64_t[16]){}, 128);
                regs[RIP] = lr;
                regs[RAX] = 0;
                regs[RSP] += 8;
                return 1;
            }
        }
        return 0;
    }*/
    else
        return 0;
    return 1;
}

void handle_fpkg_trap(uint64_t* regs, uint32_t trapno)
{
    if(trapno == 1)
    {
        uint64_t frame[12];
        pop_stack(regs, frame, sizeof(frame));
        regs[RBX] = frame[7];
        regs[R14] = frame[8];
        regs[R15] = frame[9];
        regs[RBP] = frame[10];
        regs[RIP] = frame[11];
        regs[RAX] = 0;
    }
    else if(trapno == 2)
    {
        uint64_t frame[6];
        pop_stack(regs, frame, sizeof(frame));
        regs[RIP] = (uint64_t)sceSblServiceCryptAsync_deref_singleton;
        handle_crypto_request(regs, frame[5]);
    }
}

static const uint64_t dbgregs_for_nmount[6] = {
    (uint64_t)sceSblServiceMailbox, 0, 0, 0,
    0, 0x401
};

void handle_fpkg_syscall(uint64_t* regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_nmount);
}