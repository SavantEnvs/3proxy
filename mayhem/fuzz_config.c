/* Fuzzes 3proxy's configuration parser: readconfig() over an in-memory config.
 *
 * The command table is cut down to the commands that only record settings. Commands that start
 * services, fork, run programs, load plugins, change identity, open files or query a name server
 * are left out, and so is `$file` inclusion (it reads arbitrary paths), so an input can never do
 * more than fill in 3proxy's configuration structures. A hostname resolves through `fakeresolve`.
 * `nscache`, `nscache6` and `authcache` are left out too: they pass an input-chosen size to
 * inithashtable(), which only produces multi-GB allocations (OOM, not an application bug).
 */
#include "fuzz_common.h"

extern int included;

static const char *const allowed[] = {
	"", "http", "http_content_type", "internal", "external", "timeouts", "auth", "users",
	"maxconn", "flush", "nsrecord", "fakeresolve", "dialer", "parent",
	"allow", "deny", "redirect", "bandlimin", "bandlimout", "nobandlimin", "nobandlimout",
	"countin", "nocountin", "countout", "nocountout", "countall", "nocountall", "connlim",
	"noconnlim", "logdump", "filtermaxsize", "nolog", "weight", "delimchar",
	"stacksize", "force", "noforce", "parentretries", "backlog", "maxseg", "logformat",
	"rotate", "pcre", "pcre_rewrite", "pcre_extend", "pcre_options", NULL
};

static int is_allowed(const char *name)
{
	int i;

	for(i = 0; allowed[i]; i++) if(!strcmp(name, allowed[i])) return 1;
	return 0;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	struct commands *prev = NULL, *cur, *next;

	(void)argc; (void)argv;
	fuzz_init();
	for(cur = commandhandlers; cur; cur = next){
		next = cur->next;
		if(!is_allowed(cur->command)){
			cur->next = NULL;
			continue;
		}
		if(prev) prev->next = cur;
		prev = cur;
	}
	if(prev) prev->next = NULL;
	included = 1;
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	FILE *fp;

	if(!size || size > 65536) return 0;
	fp = fmemopen((void *)data, size, "r");
	if(!fp) return 0;
	fuzz_reload_begin();
	readconfig(fp);
	conf.version++;
	fclose(fp);
	freehttprules(conf.httprules);
	conf.httprules = NULL;
	return 0;
}
