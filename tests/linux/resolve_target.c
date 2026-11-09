/* A stand-in native game for run.sh: resolves each name it is given through every libc function the plugin hooks, and
   getaddrinfo_a, which reaches getaddrinfo's own code from a worker thread, and prints "<who> <api> <name> <status>"
   (status 0 is an answer). "spawn <names...>" runs itself as a child with the names first - a child of the game, which
   inherits LD_PRELOAD and so the hook host. */
#define _GNU_SOURCE
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char* who = "parent";

static void report(const char* api, const char* name, int status)
{
    printf("%s %s %s %d\n", who, api, name, status);
    fflush(stdout);
}

static void resolve(const char* name)
{
    struct addrinfo* list = NULL;
    int status = getaddrinfo(name, "80", NULL, &list);
    report("getaddrinfo", name, status);
    if (!status) freeaddrinfo(list);

    report("gethostbyname", name, gethostbyname(name) ? 0 : h_errno);
    report("gethostbyname2", name, gethostbyname2(name, AF_INET) ? 0 : h_errno);

    struct hostent entry, *result = NULL;
    char buffer[8192];
    int error = 0;
    status = gethostbyname_r(name, &entry, buffer, sizeof buffer, &result, &error);
    report("gethostbyname_r", name, result ? 0 : (error ? error : -1));
    result = NULL;
    error = 0;
    status = gethostbyname2_r(name, AF_INET, &entry, buffer, sizeof buffer, &result, &error);
    report("gethostbyname2_r", name, result ? 0 : (error ? error : -1));
    (void)status;

    struct gaicb request = {.ar_name = name, .ar_service = "80"};
    struct gaicb* requests[] = {&request};
    status = getaddrinfo_a(GAI_WAIT, requests, 1, NULL);
    report("getaddrinfo_a", name, status ? status : gai_error(&request));
    if (!status && !gai_error(&request)) freeaddrinfo(request.ar_result);
}

int main(int argc, char** argv)
{
    if (argc > 1 && !strcmp(argv[1], "spawn"))
    {
        const pid_t child = fork();
        if (child == 0)
        {
            argv[1] = "child";
            execv("/proc/self/exe", argv);
            _exit(127);
        }
        waitpid(child, NULL, 0);
        return 0;
    }
    int first = 1;
    if (argc > 1 && !strcmp(argv[1], "child")) { who = "child"; first = 2; }
    for (int i = first; i < argc; ++i) resolve(argv[i]);
    return 0;
}
