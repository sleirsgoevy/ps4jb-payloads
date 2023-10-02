#include <string.h>
#include "fpkg.h"
#include "utils.h"
#include "traps.h"
#include "log.h"
#include "pfs_crypto.h"
#include "fakekeys.h"

extern char verifySuperBlock_call_mailbox[];
extern char sceSblServiceMailbox[];
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

static int handle_crypto_request(uint64_t* regs)
{
    uint64_t dbgregs[6] = {0};
    read_dbgregs(dbgregs);
    //if(dbgregs[0] == 0x1337)
    {
        //uint64_t req = regs[R13];
        uint64_t msg = regs[R14];
        /*if(msg != kpeek64(req))
        {
            log_word(0xdead0008dead0008);
            log_word(req);
            log_word(msg);
            return 0;
        }*/
        uint64_t msg_data[32];
        copy_from_kernel(msg_data, msg, sizeof(msg_data));
        if((msg_data[0] & 0x7fffffff) == 0x9132000) // SHA256HMAC with key handle
        {
            int idx = HANDLE_TO_IDX(msg_data[20]);
            //log_word(0xfee10006dead0000|(uint16_t)idx);
            if(idx < 0)
                return 0;
            uint8_t key[32];
            if(!get_fake_key(idx, key))
                return 0;
            if(msg_data[3] != msg_data[1] * 8)
                return 0;
            //log_word(0xdead0006dead0007);
            uint8_t hash[32] = {0};
            if(pfs_hmac_virtual(hash, key, msg_data[2], msg_data[1]))
            {
                crypto_request_emulated(regs, msg, -1);
                return 1;
            }
            /*for(int i = 0; i < 4; i++)
                log_word(*(uint64_t*)(hash+8*i));*/
            copy_to_kernel(msg+32, hash, 32);
            crypto_request_emulated(regs, msg, 0);
            return 1;
            /*for(int i = 0; i < 16; i++)
            {
                uint8_t tmp = key[i];
                key[i] = key[31-i];
                key[31-i] = tmp;
            }
            kpoke64(msg, msg_data[0] & ~(1ull << 20));
            copy_to_kernel(msg+160, key, 32);
            for(int i = 32; i < 256; i += 8)
                kpoke64(msg+i, 0x100000001);*/
        }
        else if((msg_data[0] & 0x7ffff7ff) == 0x2108000) // AES-XTS decrypt/encrypt with key handle
        {
            int idx = HANDLE_TO_IDX(msg_data[5]);
            //log_word(0xfee10006dead0100|(uint16_t)idx);
            if(idx < 0)
                return 0;
            uint8_t key[32];
            if(!get_fake_key(idx, key))
                return 0;
            if(pfs_xts_virtual(msg_data[3], msg_data[2], key, msg_data[4], msg_data[1], (msg_data[0] & 0x800) >> 11))
                crypto_request_emulated(regs, msg, -1);
            else
                crypto_request_emulated(regs, msg, 0);
            return 1;
            /*kpoke64(msg, msg_data[0] & ~(1ull << 20));
            copy_to_kernel(msg+40, key, 32);*/
        }
        /*log_word(0xdead0006dead0006);
        log_word(msg);
        for(int i = 0; i < 32; i++)
            log_word(msg_data[i]);
        log_word(0xdead0006ffffffff);*/
    }
    return 0;
}

int try_handle_fpkg_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)verifySuperBlock_call_mailbox)
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
            /*log_word(0xdead0004dead0001);
            {
                uint64_t* q = ek;
                for(int i = 0; i < 4; i++)
                    log_word(q[i]);
            }
            {
                uint64_t* q = sk;
                for(int i = 0; i < 4; i++)
                    log_word(q[i]);
            }*/
            int key1 = register_fake_key(ek);
            if(key1 >= 0)
            {
                int key2 = register_fake_key(sk);
                if(key2 >= 0)
                {
                    regs[RIP] += 5;
                    regs[RAX] = 0;
                    uint32_t fake_resp[4] = {0, 0, IDX_TO_HANDLE(key1), IDX_TO_HANDLE(key2)};
                    copy_to_kernel(regs[RDX], fake_resp, sizeof(fake_resp));
                }
            }
        }
    }
    else if(regs[RIP] == (uint64_t)sceSblServiceCryptAsync_deref_singleton)
    {
        if(!handle_crypto_request(regs))
        {
            regs[RAX] |= -1ull << 48;
            regs[RBX] |= -1ull << 48;
        }
    }
    /*else if(regs[RIP] == (uint64_t)kdata_base - 0x94a7a0)
    {
        log_word(0xdead0004dead0005);
        log_word(regs[R13]);
        log_word(regs[R14]);
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
}

static const uint64_t dbgregs_for_nmount[6] = {0x1337, (uint64_t)verifySuperBlock_call_mailbox, 0, 0, 0, 0x404};

void handle_fpkg_syscall(uint64_t* regs)
{
    start_syscall_with_dbgregs(regs, dbgregs_for_nmount);
}
