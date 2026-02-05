#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <uci.h>

static char UCI_CONFIG_FILE[128] = {'/', 'e', 't', 'c', '/', 'c', 'o', 'n', 'f', 'i', 'g', '/', 0}; 

int config_get(char* file, char *section, char *option, char *pdata, unsigned short *plen)
{
	int ret = UCI_OK;
	struct uci_context *ctx;
	struct uci_package * pkg = NULL;
	const char *value;

	ctx = uci_alloc_context();
	if (!ctx) {
		return UCI_ERR_MEM;
	}

	strcpy(&UCI_CONFIG_FILE[12], file);

	ret = uci_load(ctx, UCI_CONFIG_FILE, &pkg);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}

	struct uci_section *s = uci_lookup_section(ctx, pkg, section);
	if(s != NULL)
	{
		if (NULL != (value = uci_lookup_option_string(ctx, s, option)))
		{
			strncpy(pdata, value, 100);
			*plen = (unsigned short)strlen(pdata);
		}
		else
		{
			uci_unload(ctx, pkg);
			uci_free_context(ctx);
			ctx = NULL;
			return UCI_ERR_NOTFOUND;
		}
	}
	else
	{
		uci_unload(ctx, pkg);
		uci_free_context(ctx);
		ctx = NULL;
		return UCI_ERR_NOTFOUND;
	}

	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	ctx = NULL;
	return ret;
}


int config_set(char *file, char *section, char *option, char *pdata, unsigned short *plen)
{
	struct uci_context *ctx;
	int ret = UCI_OK;

	ctx = uci_alloc_context();
	if (!ctx) {
		return UCI_ERR_MEM;
	}

	struct uci_ptr ptr ={
		.package = "",
		.section = section,
		.option = option,
		.value = pdata,
	};

	ptr.package = file;     // no need to include "/etc/config/"

	ret = uci_set(ctx, &ptr);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}

	ret = uci_save(ctx, ptr.p);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}

#ifdef  __COMMIT_IMME
	ret = uci_commit(ctx, &ptr.p, false);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}
#endif

	uci_free_context(ctx);
	return ret;
}


static int uci_get_value(struct uci_option *o, char *out)
{
	struct uci_element *e;
	const char *delimiter = " ";
	bool sep = false;

	switch(o->type) {
	case UCI_TYPE_STRING:
		strcpy(out, o->v.string);
		break;
	case UCI_TYPE_LIST:
		uci_foreach_element(&o->v.list, e) {
			if(sep)
				strcat(out, delimiter);
			strcat(out, e->name);
			sep = true;
		}
		break;
	default:
		return UCI_ERR_INVAL;
		break;
	}

    return UCI_OK;
}

/**
 * @brief  get uci config string
 * @param  arg
 *         eg: gateway.@interface[0]
 *             gateway.interface0.serverport
 * @param  out
 * @return int
 */
int uci_get_str(char *arg, char *out)
{
	struct uci_context *ctx;
	struct uci_element *e;
	struct uci_ptr ptr;
	int ret = UCI_OK;
	char  str[256];

	strcpy(str, arg);

	if(arg == NULL || out == NULL) 
		return UCI_ERR_INVAL;

	ctx = uci_alloc_context();
	if (!ctx) {
		return UCI_ERR_MEM;
	}

	if (uci_lookup_ptr(ctx, &ptr, str, true) != UCI_OK) {
		uci_free_context(ctx);
		return UCI_ERR_NOTFOUND;
	}

	if(UCI_LOOKUP_COMPLETE & ptr.flags) {
		e = ptr.last;
		switch(e->type) {
		case UCI_TYPE_SECTION:
			ret = UCI_ERR_INVAL;
			break;
		case UCI_TYPE_OPTION:
			ret = uci_get_value(ptr.o, out);
			break;
		default:
			ret = UCI_ERR_NOTFOUND;
			break;
		}
	} else
		ret = UCI_ERR_NOTFOUND;

	uci_free_context(ctx);
	return ret;
}

/**
 * @brief
 * @param  arg
 *         eg: gateway.@interface[0]=wifi-iface
 *             gateway.interface0.serverip=10.99.20.100
 *             gateway.interface0.serverport=8000
 * @return int
 */
int uci_set_str(char *arg)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;
	int ret = UCI_OK;
	char  str[256];

	strcpy(str, arg);

	if(arg == NULL) 
		return UCI_ERR_INVAL;

	ctx = uci_alloc_context();
	if (!ctx) {
		return UCI_ERR_MEM;
	}

	if (uci_lookup_ptr(ctx, &ptr, str, true) != UCI_OK) {
		uci_free_context(ctx);
		return UCI_ERR_NOTFOUND;
	}

	ret = uci_set(ctx, &ptr);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}

	ret = uci_save(ctx, ptr.p);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}

#ifdef  __COMMIT_IMME
	ret = uci_commit(ctx, &ptr.p, false);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}
#endif

	uci_free_context(ctx);
	return ret;
}



int uci_del_str(char *arg)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;
	int ret = UCI_OK;
	char  str[256];

	strcpy(str, arg);

	if(arg == NULL) 
		return UCI_ERR_INVAL;

	ctx = uci_alloc_context();
	if (!ctx) {
		return UCI_ERR_MEM;
	}

	if (uci_lookup_ptr(ctx, &ptr, str, true) != UCI_OK) {
		uci_free_context(ctx);
		return UCI_ERR_NOTFOUND;
	}

	ret = uci_delete(ctx, &ptr);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}

	ret = uci_save(ctx, ptr.p);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}

#ifdef  __COMMIT_IMME
	ret = uci_commit(ctx, &ptr.p, false);
	if(ret != UCI_OK) {
		uci_free_context(ctx);
		return ret;
	}
#endif

	uci_free_context(ctx);
	return ret;
}


int my_uci_commit(void)
{
	struct uci_context *ctx;
	struct uci_ptr ptr;
	int ret = UCI_OK;
	char **configs = NULL;
	char **p;

	ctx = uci_alloc_context();
	if (!ctx) {
		return UCI_ERR_MEM;
	}

	if (((ret = uci_list_configs(ctx, &configs)) != UCI_OK) || !configs) {
		goto __out;
	}

	for (p = configs; *p; p++) {
		if ((ret = uci_lookup_ptr(ctx, &ptr, *p, true)) != UCI_OK) {
			goto __out;
		}
		if ((ret = uci_commit(ctx, &ptr.p, false)) != UCI_OK) {
			goto __out;
		}
	}

__out:
	uci_free_context(ctx);
	return ret;
}

