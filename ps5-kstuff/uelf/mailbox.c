#include <sys/types.h>
#include "mailbox.h"
#include "utils.h"
#include "fself.h"
#include "fpkg.h"

extern char sceSblServiceMailbox[];

int try_handle_mailbox_trap(uint64_t* regs)
{
    if(regs[RIP] == (uint64_t)sceSblServiceMailbox)
    {
        uint64_t lr = kpeek64(regs[RSP]);
        if(try_handle_fself_mailbox(regs, lr)
        || try_handle_fpkg_mailbox(regs, lr))
            return 1;
    }
    else
        return 0;
    return 1;
}
