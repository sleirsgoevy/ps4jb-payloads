#ifdef __WIN32__
#include <winsock2.h>
#include <windows.h>
#else
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#ifdef __WIN32__
typedef uint32_t in_addr_t;
typedef int socklen_t;
#define SHUT_WR SD_SEND
#define ERRNO WSAGetLastError()
#define ECONNREFUSED WSAECONNREFUSED
#define VAR_PREFIX "_"

ssize_t get_line(char** s, size_t* l, FILE* fin)
{
    size_t i = 0;
    int c;
    while((c = fgetc(fin)) != '\n' && c != EOF)
    {
        while(i + 1 >= *l)
            if(!*l)
                *l = 1;
            else
                *l += *l;
        *s = realloc(*s, *l);
        s[0][i++] = c;
    }
    if(c == EOF && !feof(fin))
        return -1;
    s[0][i] = 0;
    return i ? i : -1;
}

#else
#define SOCKET int
#define closesocket close
#define ERRNO errno
#define INVALID_SOCKET -1
#define system(...) do ; while(0)
#define VAR_PREFIX ""
#define get_line getline
#endif

asm(VAR_PREFIX"payload_data:\n.incbin \"payload.bin\"\n"VAR_PREFIX"payload_data_end:");

extern char payload_data[];
extern char payload_data_end[];

int main(int argc, const char** argv)
{
#ifdef __WIN32__
    WSADATA wsd;
    WSAStartup(0x202, &wsd);
#endif
    if(argc < 2)
    {
        fprintf(stderr, "Must specify which PKG to install\n");
        fprintf(stderr, "On Windows you can do so by dropping the .pkg \"into\" this program\n");
        system("pause");
        return 1;
    }
    in_addr_t ps4_ip = 0;
    int interactive = 0;
    if(argv[2])
        ps4_ip = inet_addr(argv[2]);
    else
    {
        printf("PS4 IP: ");
        fflush(stdout);
        char* ps4_ip_s = 0;
        size_t ps4_ip_l = 0;
        if(get_line(&ps4_ip_s, &ps4_ip_l, stdin) < 0)
        {
            free(ps4_ip_s);
            return 1;
        }
        ps4_ip = inet_addr(ps4_ip_s);
        free(ps4_ip_s);
        interactive = 1;
    }
    #define fail(act, s) do { act; fprintf(stderr, "                                                                               \r%s\n", s); if(interactive) system("pause"); return 1; } while(0)
    if(ps4_ip == 0)
        fail(, "Invalid IP address");
    FILE* pkg = fopen(argv[1], "rb");
    if(!pkg)
        fail(, "Could not open PKG file");
    SOCKET accept_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(accept_sock == INVALID_SOCKET)
        fail(fclose(pkg), "Could not create socket");
    struct sockaddr_in bind_addr = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = 0},
        .sin_port = 0,
    };
    socklen_t sl = sizeof(bind_addr);
    if(bind(accept_sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)))
        fail(fclose(pkg); closesocket(accept_sock), "Could not assign local port");
    if(getsockname(accept_sock, (struct sockaddr*)&bind_addr, &sl))
        fail(fclose(pkg); closesocket(accept_sock), "Could not get local port");
    if(listen(accept_sock, 1))
        fail(fclose(pkg); closesocket(accept_sock), "Failed to put socket into listening mode");
    struct sockaddr_in connect_addr = {
        .sin_family = AF_INET,
        .sin_addr = {.s_addr = ps4_ip},
        .sin_port = htons(9021)
    };
retry_connect:;
    SOCKET connect_sock = socket(AF_INET, SOCK_STREAM, 0);
    if(connect_sock == INVALID_SOCKET)
        fail(closesocket(accept_sock), "Could not create socket");
    if(connect(connect_sock, (struct sockaddr*)&connect_addr, sizeof(connect_addr)))
    {
        if(ERRNO == ECONNREFUSED && connect_addr.sin_port == htons(9021))
        {
            connect_addr.sin_port = htons(9020);
            closesocket(connect_sock);
            goto retry_connect;
        }
        fail(fclose(pkg); closesocket(accept_sock); closesocket(connect_sock), "Could not connect to PS4");
    }
    if(getsockname(connect_sock, (struct sockaddr*)&connect_addr, &sl))
        fail(fclose(pkg); closesocket(accept_sock); closesocket(connect_sock), "Could not get local address");
    size_t sz = payload_data_end - payload_data;
    char* p0 __attribute__((may_alias)) = malloc(sz);
    char* p __attribute__((may_alias)) = p0;
    if(!p)
        fail(fclose(pkg); closesocket(accept_sock); closesocket(connect_sock), "Could not allocate memory for payload");
    memcpy(p, payload_data, sz);
    size_t nb3 = 0;
    size_t b3_offset = sz;
    struct {
        uint32_t addr;
        uint16_t port;
        uint64_t pkg_size;
    } __attribute__((packed,may_alias))* argument;
#ifdef __WIN32__
    for(size_t i = 0; i < sz; i++)
    {
        if(p[i] == (char)0xb3)
            nb3++;
        else
            nb3 = 0;
        if(nb3 == 14)
        {
            b3_offset = i - 13;
            break;
        }
    }
    argument = (void*)(p + b3_offset);
#else
    argument = memmem(p, sz, "\xb3\xb3\xb3\xb3\xb3\xb3\xb3\xb3\xb3\xb3\xb3\xb3\xb3\xb3", 14);
#endif
    argument->addr = connect_addr.sin_addr.s_addr;
    argument->port = bind_addr.sin_port;
    if(fseeko(pkg, 0, SEEK_END))
        fail(fclose(pkg); closesocket(accept_sock); closesocket(connect_sock), "File is not seekable");
    off_t file_size = argument->pkg_size = ftello(pkg);
    if(file_size == (off_t)-1)
        fail(fclose(pkg); closesocket(accept_sock); closesocket(connect_sock), "Could not determine file size");
    fseek(pkg, 0, SEEK_SET);
    while(sz > 0)
    {
        ssize_t chk = send(connect_sock, p, sz, 0);
        if(chk <= 0)
            fail(closesocket(accept_sock); closesocket(connect_sock), "Could not send payload");
        p += chk;
        sz -= chk;
    }
    closesocket(connect_sock);
    free(p0);
    SOCKET send_sock = accept(accept_sock, NULL, NULL);
    if(send_sock == INVALID_SOCKET)
        fail(fclose(pkg); closesocket(accept_sock), "Could not accept PKG request");
    closesocket(accept_sock);
    off_t total = 0;
    char buf[4096], buf2[4096];
    ssize_t chk = 0;
    char* p2 = buf;
    for(;;)
    {
        fd_set rd, wr;
        FD_ZERO(&rd);
        FD_SET(send_sock, &rd);
        FD_ZERO(&wr);
        FD_SET(send_sock, &wr);
        if(select(send_sock + 1, &rd, &wr, NULL, NULL) <= 0)
            fail(fclose(pkg); closesocket(send_sock), "select() failed");
        if(FD_ISSET(send_sock, &rd))
        {
            if(recv(send_sock, buf2, sizeof(buf2), 0) <= 0)
                fail(fclose(pkg); closesocket(send_sock), "Connection closed by PS4");
            continue;
        }
        if(!FD_ISSET(send_sock, &wr))
            continue;
        if(chk == 0)
        {
            chk = fread(buf, 1, sizeof(buf), pkg);
            if(chk < 0)
                fail(fclose(pkg); closesocket(send_sock), "Failed to read from file");
            if(chk == 0)
                break;
            p2 = buf;
        }
        ssize_t chk2 = send(send_sock, p2, chk, 0);
        if(chk2 <= 0)
            fail(fclose(pkg); closesocket(send_sock), "Failed to send data");
        total += chk2;
        p2 += chk2;
        chk -= chk2;
        fprintf(stderr, "%"PRIu64" of %"PRIu64" bytes transmitted (%.1f%%)     \r", (uint64_t)total, (uint64_t)file_size, total * (double)100 / file_size);
        fflush(stderr);
    }
    fclose(pkg);
    //receive remaining acks
    shutdown(send_sock, SHUT_WR);
    while(recv(send_sock, buf2, sizeof(buf2), 0) > 0);
    closesocket(send_sock);
    if(total != file_size)
        fail(, "Sanity check failed: transmitted size not equal to file size");
    fprintf(stderr, "                                                                               \rPKG transmitted successfully\n");
    if(interactive)
        system("pause");
    return 0;
}
