#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include <glib.h>

#include <pkgmgr_parser.h>
#include <tzplatform_config.h>

#define OWNER_ROOT 0
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define UG_CLIENT tzplatform_mkpath(TZ_SYS_BIN, "ug-client")

static int _check_bin_directory(const char *pkgid)
{
	const char *path;
	char buf[PATH_MAX];

	path = tzplatform_mkpath(TZ_SYS_RO_APP, pkgid);
	snprintf(buf, sizeof(buf), "%s/bin", path);

	if (access(buf, F_OK) == 0)
		return 0;

	if (mkdir(buf, S_IRWXU | S_IRGRP | S_IXGRP | S_IXOTH)) {
		printf("create bin directory(%s) failed: %s\n", buf,
				strerror(errno));
		return -1;
	}

	return 0;
}

static void _application_cb(gpointer data, gpointer user_data)
{
	int ret;
	application_x *app = (application_x *)data;
	package_x *pkg = (package_x *)user_data;

	if (app->exec == NULL || app->ui_gadget == NULL ||
			strcasecmp(app->ui_gadget, "true") != 0)
		return;

	if (_check_bin_directory(pkg->package))
		return;

	ret = symlink(UG_CLIENT, app->exec);
	if (ret != 0)
		printf("failed to install ug %s: %s\n", app->exec,
				strerror(errno));
}

static int _install_ug(char *manifest)
{
	package_x *pkg;

	pkg = pkgmgr_parser_process_manifest_xml(manifest);
	if (pkg == NULL) {
		printf("Parse manifest failed\n");
		return -1;
	}

	g_list_foreach(pkg->application, _application_cb, pkg);
	pkgmgr_parser_free_manifest_xml(pkg);

	return 0;
}

static void _print_usage(const char *cmd)
{
	printf("usage: %s <manifest>\n", cmd);
}

int main(int argc, char *argv[])
{
	if (getuid() != OWNER_ROOT && getuid() != GLOBAL_USER) {
		printf("Only root or tizenglobalapp user is allowed\n");
		return -1;
	}

	if (argc < 2) {
		_print_usage(argv[0]);
		return -1;
	}

	return _install_ug(argv[1]);
}
