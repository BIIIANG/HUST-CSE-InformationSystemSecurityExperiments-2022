#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "handle.h"
#include "http.h"
#include "parse.h"

#include <seccomp.h>
#include <unistd.h>
#define DEBUG 1

static void error(int fd, int errcode, char* msg);
static void parse(int fd);

void init_seccomp() {

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) { exit(-1); }

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigaction), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socketcall), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(clone), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(set_robust_list), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getresuid32), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getcwd), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(getpid), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(statx), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(close), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(_llseek), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fcntl64), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(access), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchmod), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(geteuid32), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchown32), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fsync), 0) < 0) { exit(-1); }

#if 1
    // for get shell, but fail because the conflict of mount
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigprocmask), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap2), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(execve), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mount), 0) < 0) { exit(-1); }
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(wait4), 0) < 0) { exit(-1); }
#endif

    // if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(unlink), 0) < 0) { exit(-1); }

    if (seccomp_load(ctx) < 0) { exit(-1); }
    
    seccomp_release(ctx);
}

// utilities
void die(const char* msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(0);
}

void kprint(const char* msg) {
    write(1, msg, sizeof(msg));
    return;
}

void write_file(int sockfd, const char* s) {
    int size = strlen(s);

    write(sockfd, s, size);
    return;
}

int main(int argc, char** argv) {
    Http_t tree;

    if (argc < 2)
        die("server bug");

    signal(SIGCHLD, SIG_IGN);

    init_seccomp();

    // get the pipe fd
    int pipefd = atoi(argv[1]);
    if (DEBUG)
        printf("pipefd = %d\n", pipefd);

    while (1) {
        char uri_str[1024];
        int sockfd;
        recvfd(pipefd, uri_str, sizeof(uri_str), &sockfd);
        printf("uri = %s\n", uri_str);
        // int sockfd = atoi (sockfd_str);
        if (DEBUG)
            printf("mailsv client recieves a sockfd = %d\n", sockfd);

        if (fork() == 0)  // child
        {
            int ruid, euid, suid;
            getresuid(&ruid, &euid, &suid);
            printf("uid = %d %d %d \n", ruid, euid, suid);

            setReqline(REQ_KIND_POST, uri_str);
            tree = Parse_parse(sockfd, 0);

            // response
            Handle_main(sockfd, tree);

            close(sockfd);
            exit(0);
        }

        close(sockfd);
    }

    return 0;
}

////////////////////////////////////////////
// parser
void error(int fd, int errCode, char* msg) {
    int c;

    while (read(fd, &c, 1) != -1)
        ;
    close(fd);

    fprintf(stderr, "%d\n", errCode);
    fprintf(stderr, "%s\n", msg);
    exit(0);
    return;
}
