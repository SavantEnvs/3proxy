/* Fuzzes the client-facing side of one 3proxy service: the bytes a client sends on a connection.
 *
 * The service is set up the way a configuration file would (the real command parser, the real
 * srvinit/childfunc), but the "client" is one end of a socketpair. Each input is written to it, then
 * the write side is closed, so a child that waits for more finds end-of-file at once and never waits
 * out a timeout. The service never connects out: proxy, socks, mail and ftp services run with `deny *`
 * (parsing and authentication run, then the request is refused), and the HTTP server answers from its
 * own rules (echo, data, reply, redir, rewrite, file, cache).
 *
 * One source, one service per build: FUZZ_HTTPSRV, FUZZ_PROXY, FUZZ_SOCKS, FUZZ_POP3P, FUZZ_SMTPP,
 * FUZZ_IMAPP or FUZZ_FTPPR.
 */
#include "fuzz_common.h"
#include <fcntl.h>
#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined FUZZ_HTTPSRV
#define CHILD httpsrvchild
#define SERVICE S_HTTPSRV
#define SERVICE_CONFIG \
	"auth iponly\n" \
	"allow *\n" \
	"http_content_type html text/html\n" \
	"http echo * /echo**\n" \
	"http data * /data**\n" \
	"http reply * /ok**\n" \
	"http reply * /down** 503 \"Retry-After: 30\"\n" \
	"http redir * /moved** 301 \"http://example.org/x$1\"\n" \
	"http rewrite * /alias/** \"/echo/$1\"\n" \
	"http rewrite_host *.old.example ** \"$1.new.example\"\n" \
	"http file * /f/*.html \"mayhem/www/$1.html\"\n" \
	"http cache * /c/*.html \"mayhem/www/$1.html\" * 60\n" \
	"http echo * /**\n"
#elif defined FUZZ_PROXY
#define CHILD proxychild
#define SERVICE S_PROXY
#elif defined FUZZ_SOCKS
#define CHILD sockschild
#define SERVICE S_SOCKS
#elif defined FUZZ_POP3P
#define CHILD pop3pchild
#define SERVICE S_POP3P
#elif defined FUZZ_SMTPP
#define CHILD smtppchild
#define SERVICE S_SMTPP
#elif defined FUZZ_IMAPP
#define CHILD imappchild
#define SERVICE S_IMAPP
#elif defined FUZZ_FTPPR
#define CHILD ftpprchild
#define SERVICE S_FTPPR
#else
#error "select a service: FUZZ_HTTPSRV, FUZZ_PROXY, FUZZ_SOCKS, FUZZ_POP3P, FUZZ_SMTPP, FUZZ_IMAPP or FUZZ_FTPPR"
#endif

#ifndef SERVICE_CONFIG
#define SERVICE_CONFIG "auth iponly\ndeny *\n"
#endif

#define MAXINPUT 65536

void *CHILD(struct clientparam *param);

static struct srvparam srv;
static struct clientparam defparam;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	static char config[] = SERVICE_CONFIG;
	FILE *fp;

	(void)argc; (void)argv;
	fuzz_init();
	fuzz_reload_begin();
	fp = fmemopen(config, sizeof(config) - 1, "r");
	if(!fp || readconfig(fp)) abort();
	fclose(fp);

	srvinit(&srv, &defparam);
	srv.pf = CHILD;
	srv.service = defparam.service = SERVICE;
	srv.acl = copyacl(conf.acl);
	srv.authfuncs = copyauth(conf.authfuncs);
#ifdef WITH_HTTPSRV
	srv.httprules = conf.httprules;
	conf.httprules = NULL;
#endif
	srvinit2(&srv, &defparam);
	return 0;
}

/* Reads and discards what the service writes back, so a long reply never fills the socket buffer
   and stalls the child. Ends when the child closes its side. */
static void *drain(void *arg)
{
	char buf[4096];
	int fd = (int)(intptr_t)arg;

	while(read(fd, buf, sizeof(buf)) > 0);
	return NULL;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct clientparam *param;
	pthread_t reader;
	int sv[2];
	size_t done = 0;

	if(size > MAXINPUT) size = MAXINPUT;
	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return 0;
	while(done < size){
		ssize_t n = write(sv[1], data + done, size - done);

		if(n <= 0) break;
		done += (size_t)n;
	}
	shutdown(sv[1], SHUT_WR);

	param = malloc(sizeof(*param));
	if(!param || pthread_create(&reader, NULL, drain, (void *)(intptr_t)sv[1])){
		free(param);
		close(sv[0]);
		close(sv[1]);
		return 0;
	}
	*param = defparam;
	param->clisock = sv[0];
	fcntl(sv[0], F_SETFL, O_NONBLOCK | fcntl(sv[0], F_GETFL));
	childfunc(param);
	pthread_join(reader, NULL);
	close(sv[1]);
	return 0;
}
