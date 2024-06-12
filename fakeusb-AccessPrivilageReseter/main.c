#include <unistd.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <signal.h>

int main()
{
    chmod("/user/home/fakeusb", 0777);
    return 0;
}
