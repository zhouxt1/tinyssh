/*
TCP-listener front-end for tinysshd.

Upstream tinysshd is inetd-style: it speaks SSH on stdin/stdout and is meant to
be invoked behind tcpserver/socat/inetd. That setup defeats AFL coverage --
the launcher process is uninstrumented (or, for an instrumented launcher that
exec's tinysshd, the exec boundary kills the forkserver handshake and forces
edge-id collisions across the two binaries).

This file replaces the launcher with a single instrumented binary that does
its own socket/bind/listen/accept, dup2's the connection onto fd 0/1, and then
calls main_tinysshd() *as a function* (no exec). One process, one set of edge
ids, one forkserver -- AFL/AFLNet sees coverage the same way it does for
OpenSSH's `sshd -d -r`.

Usage: tinysshd-listen <port> <keydir> [extra tinysshd args...]
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "main.h"

int main(int argc, char **argv) {

    if (argc < 3) {
        fprintf(stderr, "usage: %s <port> <keydir> [tinysshd-args...]\n",
                argc > 0 ? argv[0] : "tinysshd-listen");
        return 100;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port: %s\n", argv[1]);
        return 100;
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return 111; }

    int one = 1;
    (void)setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 111; }
    if (listen(s, 1) < 0) { perror("listen"); return 111; }

    int c = accept(s, NULL, NULL);
    if (c < 0) { perror("accept"); return 111; }

    if (dup2(c, 0) < 0 || dup2(c, 1) < 0) { perror("dup2"); return 111; }
    if (c > 1) close(c);
    close(s);

    /* Reshape argv so tinysshd sees [progname, keydir, extras...]. The slot
       that held our <port> argument is reused for the synthetic progname. */
    argv[1] = (char *)"tinysshd";
    return main_tinysshd(argc - 1, argv + 1, "tinysshd");
}
