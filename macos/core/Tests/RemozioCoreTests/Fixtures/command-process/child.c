/* Unprivileged synthetic launcher and program. This fixture is never embedded or installed. */
#include "RemozioCommandChild.h"
#include <errno.h>
#include <limits.h>
#include <libproc.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <termios.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/ioctl.h>
#include <unistd.h>
static uint32_t word(const unsigned char *b) { return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|((uint32_t)b[2]<<8)|b[3]; }
static int exact(int fd, void *value, size_t count) {
    size_t used=0;
    while(used<count) {
        ssize_t n=read(fd,(char *)value+used,count-used);
        if(n<0 && errno==EINTR)continue;
        if(n<=0)return 1;
        used+=(size_t)n;
    }
    return 0;
}
static int mapped_probe(const char *mask_word) {
        char *end=NULL; long mask=strtol(mask_word, &end, 10);
        if(!end || *end || mask<0 || mask>7)return 110;
        for(int fd=3;fd<256;fd++)if(fcntl(fd,F_GETFD)>=0)return 111;
        int terminal=open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
        struct proc_bsdinfo context;
        if(terminal<0 || proc_pidinfo(getpid(),PROC_PIDTBSDINFO,0,&context,sizeof(context))!=(int)sizeof(context) ||
            tcgetsid(terminal)!=getsid(0) || tcgetpgrp(terminal)!=getpgrp())return 112;
        for(int fd=0;fd<3;fd++) {
            struct stat stream;
            if(fstat(fd,&stream))return 113;
            int same=S_ISCHR(stream.st_mode) && (uint32_t)stream.st_rdev==context.e_tdev;
            if(same != !!(mask & (1<<fd)))return 114;
            if(same && ((fcntl(fd,F_GETFL)&O_ACCMODE)!=O_RDWR || tcgetsid(fd)!=getsid(0)))return 115;
        }
        close(terminal);
        if(write(1,"OUT",3)!=3 || write(2,"ERR",3)!=3)return 116;
        return 7;
}
int main(int argc, char **argv) {
    if(argc==2 && (!strcmp(argv[1],"--execute") || !strcmp(argv[1],"--execute-in-session"))) {
        bool in_session = !strcmp(argv[1],"--execute-in-session");
        if(strstr(argv[0],"held-prepare-child")) {
            char ready[PATH_MAX];if(snprintf(ready,sizeof(ready),"%s.ready",argv[0])>=(int)sizeof(ready))return 70;
            while(access(ready,F_OK)){if(errno!=ENOENT)return 70;usleep(1000);}
        }
        if(strstr(argv[0],"stalled-child")) {for(;;)pause();}
        unsigned char header[40]={0};
        if(exact(3,header,40))return 70;
        size_t count=40+word(header+4);
        if(count>REMOZIO_CHILD_MAX_BYTES)return 70;
        unsigned char *bytes=malloc(count);if(!bytes)return 70;
        memcpy(bytes,header,40);if(exact(3,bytes+40,count-40))return 70;
        unsigned char extra=0;if(read(3,&extra,1)!=0)return 70;close(3);
        remozio_child_spec_t spec={0};if(remozio_child_spec_decode(bytes,count,&spec))return 70;free(bytes);
        if(fchdir(4))return 70;close(4);
        if(in_session && (getsid(0)==getpid() || getsid(0)!=getsid(getppid()) || getpgrp()!=getpid()))return 70;
        if(spec.io_mode != 0) {
            int terminal = spec.io_mode == 2 ? 7 : 0;
            int streams[3] = {0, 1, 2};
            if(spec.io_mode == 2 && remozio_child_spec_validate_stdio(&spec, terminal, streams))return 70;
            if(in_session ? (tcgetsid(terminal)!=getsid(0) || tcgetpgrp(terminal)!=getpgrp()) : (getsid(0)!=getpid() || ioctl(terminal,TIOCSCTTY,0)))return 70;
        }
        close(7);
        if(fcntl(5,F_SETFD,FD_CLOEXEC))return 70;
        unsigned char ready[12]={0x52,0x4d,0x52,0x31,0,0,0,1,0,0,0,0};
        if(strstr(argv[0],"malformed-child")) {ready[0]=0;write(5,ready,12);return 70;}
        if(strstr(argv[0],"truncated-child")) {write(5,ready,7);return 70;}
        if(strstr(argv[0],"closed-release-child"))close(6);
        if(write(5,ready,12)!=12)return 70;
        if(strstr(argv[0],"closed-release-child")) {for(;;)pause();}
        if(strstr(argv[0],"closed-status-child")) {close(5);for(;;)pause();}
        unsigned char release=0;if(exact(6,&release,1)||release!=1)return 70;close(6);
        if(strstr(argv[0],"late-fault-child")) {unsigned char extra=1;write(5,&extra,1);}
        execve(spec.executable,spec.arguments,spec.environment);
        int error=errno;unsigned char failed[12]={0x52,0x4d,0x52,0x31,0,0,0,2,0,0,0,0};
        for(unsigned i=0;i<4;i++)failed[8+i]=(unsigned char)((uint32_t)error>>((3U-i)*8));
        (void)write(5,failed,sizeof failed);return 70;
    }
    if(argc==4 && !strcmp(argv[1], "mapped-probe")) {
        int result=mapped_probe(argv[2]);
        int report=open(argv[3],O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        char value[16];int length=snprintf(value,sizeof(value),"%d",result);
        if(report<0 || length<=0 || write(report,value,(size_t)length)!=length)return 117;
        close(report);return result;
    }
    if(argc!=4 || (unsigned char)argv[0][0]!=0xff || argv[0][1] || argv[1][0] ||
        (unsigned char)argv[2][0]!=0xfe || argv[2][1])return 91;
    char *raw=getenv("RAW"), *empty=getenv("EMPTY");
    if(!raw || (unsigned char)raw[0]!=0xfd || raw[1] || !empty || *empty || getenv("PATH"))return 92;
    for(int fd=3;fd<256;fd++)if(fcntl(fd,F_GETFD)>=0)return 93;
    if(getpgrp()!=getpid())return 94;
    if(!strcmp(argv[3],"pty")) {if(!isatty(0)||tcgetsid(0)!=getsid(0)||tcgetpgrp(0)!=getpgrp())return 99;return write(1,"PTY",3)==3?7:98;}
    if(!strcmp(argv[3],"pty-bulk") || !strcmp(argv[3],"pty-infinite")) {
        if(!isatty(0)||tcgetsid(0)!=getsid(0)||tcgetpgrp(0)!=getpgrp())return 99;
        size_t offset=0;unsigned char block[4096];
        do {
            for(size_t i=0;i<sizeof(block);i++)block[i]=(unsigned char)((offset+i)%251);
            size_t used=0;
            while(used<sizeof(block)) {
                ssize_t n=write(1,block+used,sizeof(block)-used);
                if(n<0&&errno==EINTR)continue;
                if(n<=0)return 98;
                used+=(size_t)n;
            }
            offset+=sizeof(block);
        } while(!strcmp(argv[3],"pty-infinite")||offset<1048576);
        return 7;
    }
    if(!strcmp(argv[3],"plain_stop") || !strcmp(argv[3],"trace_stop") || !strcmp(argv[3],"trace_trap")) {
        if(strcmp(argv[3],"plain_stop") && ptrace(PT_TRACE_ME,0,NULL,0))return 103;
        if(raise(!strcmp(argv[3],"trace_trap") ? SIGTRAP : SIGSTOP))return 104;
        return 7;
    }
    if(!strcmp(argv[3],"signal")) {raise(SIGTERM);return 95;}
    if(!strcmp(argv[3],"short-wait")) {usleep(300000);return 0;}
    if(!strcmp(argv[3],"wait")) {for(;;)pause();}
    if(!strcmp(argv[3],"sigwait")) {
        sigset_t signals;sigemptyset(&signals);sigaddset(&signals,SIGCONT);
        if(sigprocmask(SIG_BLOCK,&signals,NULL)||write(1,"WAIT\n",5)!=5)return 101;
        for(;;){int number=0;if(sigwait(&signals,&number)||number!=SIGCONT)return 102;}
    }
    struct stat held,named;if(stat(".",&held)||stat(getenv("CWD"),&named)||held.st_ino!=named.st_ino||held.st_dev!=named.st_dev)return 96;
    char input[64]={0};ssize_t n=read(0,input,sizeof(input));if(n<0)return 97;
    if(write(1,"OUT:",4)!=4 || write(1,input,(size_t)n)!=n || write(2,"ERR",3)!=3)return 98;
    return 7;
}
