/* Process setup shared by the harnesses: what 3proxy's main() does before it reads a configuration. */
#ifndef FUZZ_COMMON_H
#define FUZZ_COMMON_H

#include "proxy.h"
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_SSL
void ssl_install(void);
#endif
#ifdef WITH_PCRE
void pcre_install(void);
#endif
#ifdef WITH_TRANSPARENT
void transparent_install(void);
#endif
#ifdef WITH_HTTPSRV
void httpsrv_init(void);
#endif
extern unsigned char *strings[];

static void fuzz_init(void)
{
	signal(SIGPIPE, SIG_IGN);
	conf.stringtable = strings;
	_3proxy_mutex_init(&config_mutex);
	_3proxy_mutex_init(&runningservices_mutex);
	_3proxy_mutex_init(&bandlim_mutex);
	_3proxy_mutex_init(&connlim_mutex);
	_3proxy_mutex_init(&tc_mutex);
	_3proxy_mutex_init(&log_mutex);
#ifndef NORADIUS
	_3proxy_mutex_init(&rad_mutex);
#endif
	_3proxy_sem_init_timed(serviceexited, 0, 0x7fffffff);
	initcommands();
}

/* The start of a (re)load: what reload() does before readconfig(), then names resolve to a fixed
   fake address so a configuration can never reach a name server. freeconf() does not reset every
   setting a configuration can change (delimchar, stacksize, ...), nor the global `timeouts` array,
   nor the name-server and auth caches, so the first call keeps the cleaned `conf` and `timeouts`
   and every later one restores them and destroys the caches: an input's result then depends on
   that input alone. The `authfuncs` list is the exception: freeconf() frees the old one and
   builds a new one on every call, so the snapshot's pointer is stale and the fresh list is kept. */
static void fuzz_reload_begin(void)
{
	static struct extparam clean;
	static int clean_timeouts[sizeof(timeouts) / sizeof(timeouts[0])];
	static int have_clean;
	static char fake[] = "fakeresolve\n";
	FILE *fp;

#ifdef WITH_SSL
	ssl_install();
#endif
#ifdef WITH_PCRE
	pcre_install();
#endif
#ifdef WITH_TRANSPARENT
	transparent_install();
#endif
#ifdef WITH_HTTPSRV
	httpsrv_init();
#endif
	freeconf(&conf);
	destroyhashtable(&dns_table);
	destroyhashtable(&dns6_table);
	destroyhashtable(&auth_table);
	if(have_clean){
		struct auth *authfuncs = conf.authfuncs;

		free(conf.demanddialprog);
		conf = clean;
		conf.authfuncs = authfuncs;
		memcpy(timeouts, clean_timeouts, sizeof(timeouts));
	}
	else{
		clean = conf;
		memcpy(clean_timeouts, timeouts, sizeof(timeouts));
		have_clean = 1;
	}
	fp = fmemopen(fake, sizeof(fake) - 1, "r");
	if(fp){
		readconfig(fp);
		fclose(fp);
	}
}

#endif
