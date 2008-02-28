/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "istream.h"
#include "imap-parser.h"
#include "test-parser.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>

#define DEFAULT_MBOX_FNAME "default.mbox"

struct test_parser {
	pool_t pool;
	const char *dir, *default_mbox_path;

	struct imap_arg *reply_ok, *reply_no, *reply_bad;
	struct test_command *cur_cmd;
	ARRAY_TYPE(test) tests;
};

static bool
test_parse_header_line(struct test_parser *parser, struct test *test,
		       const char *line, const char **error_r)
{
	const char *key, *value;

	value = strchr(line, ':');
	if (value == NULL) {
		*error_r = "Missing ':'";
		return FALSE;
	}

	for (key = value; key[-1] == ' '; key--) ;
	key = t_str_lcase(t_strdup_until(line, key));
	for (value++; *value == ' '; value++) ;

	if (strcmp(key, "capabilities") == 0) {
		test->required_capabilities = (const char *const *)
			p_strsplit_spaces(parser->pool, value, " ");
		return TRUE;
	}
	if (strcmp(key, "connections") == 0) {
		test->connection_count = strcmp(value, "n") == 0 ? 2 :
			strtoul(value, NULL, 10);
		return TRUE;
	}
	if (strcmp(key, "state") == 0) {
		if (strcasecmp(value, "nonauth") == 0)
			test->login_state = LSTATE_NONAUTH;
		else if (strcasecmp(value, "auth") == 0)
			test->login_state = LSTATE_AUTH;
		else if (strcasecmp(value, "selected") == 0)
			test->login_state = LSTATE_SELECTED;
		else {
			*error_r = "Unknown state value";
			return FALSE;
		}
		return TRUE;
	}

	*error_r = "Unknown setting";
	return FALSE;
}

static void
test_parse_imap_arg_dup(pool_t pool, const struct imap_arg *args,
			struct imap_arg *dup)
{
	const struct imap_arg *subargs;
	struct imap_arg *subdub;
	unsigned int i, count;

	dup->type = args->type;
	switch (dup->type) {
	case IMAP_ARG_NIL:
	case IMAP_ARG_EOL:
		break;
	case IMAP_ARG_ATOM:
	case IMAP_ARG_STRING:
		dup->_data.str = p_strdup(pool, args->_data.str);
		break;
	case IMAP_ARG_LIST:
		subargs = array_get(&args->_data.list, &count);
		p_array_init(&dup->_data.list, pool, count);
		for (i = 0; i < count; i++) {
			subdub = array_append_space(&dup->_data.list);
			test_parse_imap_arg_dup(pool, &subargs[i], subdub);
		}
		break;
	default:
		i_unreached();
	}
}

static const struct imap_arg *
test_parse_imap_args_dup(pool_t pool, const struct imap_arg *args)
{
	ARRAY_TYPE(imap_arg_list) list;
	struct imap_arg *dub;
	unsigned int i, count = 0;

	while (args[count++].type != IMAP_ARG_EOL) ;

	p_array_init(&list, pool, count);
	for (i = 0; i < count; i++) {
		dub = array_append_space(&list);
		test_parse_imap_arg_dup(pool, &args[i], dub);
	}
	return array_idx(&list, 0);
}

static const struct imap_arg *
test_parse_imap_args(struct test_parser *parser, const char *line,
		     const char **error_r)
{
	struct imap_parser *imap_parser;
	struct istream *input;
	const struct imap_arg *args;
	bool fatal;
	int ret;

	input = i_stream_create_from_data(line, strlen(line));
	imap_parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(imap_parser, 0,
				      IMAP_PARSE_FLAG_ATOM_ALLCHARS, &args);
	if (ret < 0) {
		args = NULL;
		if (ret == -2)
			*error_r = "Missing data";
		else {
			*error_r = t_strdup(imap_parser_get_error(imap_parser,
								  &fatal));
		}
	} else {
		args = test_parse_imap_args_dup(parser->pool, args);
	}
	imap_parser_destroy(&imap_parser);
	i_stream_unref(&input);
	return args;
}

static bool
test_parse_command_untagged(struct test_parser *parser,
			    const char *line, const char **error_r)
{
	struct test_command *cmd = parser->cur_cmd;
	const struct imap_arg *args;

	if (!array_is_created(&cmd->untagged))
		p_array_init(&cmd->untagged, parser->pool, 8);

	args = test_parse_imap_args(parser, line, error_r);
	if (args == NULL)
		return FALSE;

	array_append(&cmd->untagged, &args, 1);
	return TRUE;
}

static bool
test_parse_command_finish(struct test_parser *parser,
			  const char *line, const char **error_r)
{
	struct test_command *cmd = parser->cur_cmd;

	cmd->reply = test_parse_imap_args(parser, line, error_r);
	return cmd->reply != NULL;
}

static bool
test_parse_command_line(struct test_parser *parser, struct test *test,
			const char *line, const char **error_r)
{
	struct test_command *cmd;

	if (parser->cur_cmd != NULL) {
		if (strncmp(line, "* ", 2) == 0) {
			return test_parse_command_untagged(parser, line + 2,
							   error_r);
		} else if (parser->cur_cmd->reply == NULL) {
			return test_parse_command_finish(parser, line, error_r);
		}
	}

	if (parser->cur_cmd != NULL && parser->cur_cmd->reply == NULL) {
		*error_r = "Missing command reply line";
		return FALSE;
	}

	cmd = p_new(parser->pool, struct test_command, 1);
	if (test->connection_count > 1) {
		/* begins with connection index */
		if (!is_numeric(line, ' ') || *line == '0') {
			*error_r = "Missing client index";
			return FALSE;
		}

		cmd->connection_idx = strtoul(line, NULL, 10);
		i_assert(cmd->connection_idx > 0);
		if (test->connection_count < cmd->connection_idx)
			test->connection_count = cmd->connection_idx;
		cmd->connection_idx--;

		line = strchr(line, ' ');
		if (line++ == NULL)
			line = "";
	}

	/* optional expected ok/no/bad reply */
	if (strncasecmp(line, "ok ", 3) == 0) {
		cmd->reply = parser->reply_ok;
		line += 3;
	} else if (strncasecmp(line, "no ", 3) == 0) {
		cmd->reply = parser->reply_no;
		line += 3;
	} else if (strncasecmp(line, "bad ", 4) == 0) {
		cmd->reply = parser->reply_bad;
		line += 4;
	}

	cmd->command = p_strdup(parser->pool, line);
	parser->cur_cmd = cmd;
	array_append(&test->commands, &cmd, 1);
	return TRUE;
}

static bool test_parse_file(struct test_parser *parser, struct test *test,
			    struct istream *input)
{
	const char *line, *error;
	unsigned int linenum = 0;
	bool ret, header = TRUE;

	parser->cur_cmd = NULL;
	while ((line = i_stream_read_next_line(input)) != NULL) {
		linenum++;
		if (*line == '\0') {
			parser->cur_cmd = NULL;
			header = FALSE;
			continue;
		}
		if (*line == '#')
			continue;

		T_BEGIN {
			if (header) {
				ret = test_parse_header_line(parser, test,
							     line, &error);
			} else {
				ret = test_parse_command_line(parser, test,
							      line, &error);
			}
		} T_END;

		if (!ret) {
			i_error("%s line %u: %s", test->path, linenum, error);
			return FALSE;
		}
	}
	if (parser->cur_cmd != NULL && parser->cur_cmd->reply == NULL) {
		i_error("%s line %u: Missing command reply line",
			test->path, linenum);
		return FALSE;
	}
	return TRUE;
}

static int
test_parser_read_test(struct test_parser *parser, const char *fname,
		      const struct test **test_r)
{
	struct test *test;
	struct istream *input;
	struct stat st;
	const char *mbox_path;
	int fd, ret = 0;

	test = p_new(parser->pool, struct test, 1);
	test->login_state = LSTATE_SELECTED;
	test->connection_count = 1;
	p_array_init(&test->commands, parser->pool, 32);

	mbox_path = t_strdup_printf("%s/%s.mbox", parser->dir, fname);
	if (stat(mbox_path, &st) == 0) {
		/* test-specific mbox */
		test->mbox_source_path = p_strdup(parser->pool, mbox_path);
	} else if (errno != ENOENT) {
		i_error("stat(%s) failed: %m", mbox_path);
		return -1;
	} else {
		/* use the default mbox */
		test->mbox_source_path = parser->default_mbox_path;
	}

	test->path = p_strdup_printf(parser->pool, "%s/%s", parser->dir, fname);
	test->name = test->path + strlen(parser->dir) + 1;
	if (stat(test->path, &st) < 0) {
		i_error("stat(%s) failed: %m", test->path);
		return -1;
	}
	if (!S_ISREG(st.st_mode))
		return 0;

	fd = open(test->path, O_RDONLY);
	if (fd == -1) {
		i_error("open(%s) failed: %m", test->path);
		return -1;
	}

	input = i_stream_create_fd(fd, (size_t)-1, FALSE);
	if (!test_parse_file(parser, test, input))
		ret = -1;
	i_stream_unref(&input);
	if (close(fd) < 0) {
		i_error("close(%s) failed: %m", test->path);
		return -1;
	}
	*test_r = test;
	return ret < 0 ? -1 : 1;
}

static int test_parser_scan_dir(struct test_parser *parser)
{
	const struct test *test;
	DIR *dir;
	struct dirent *d;
	unsigned int len;
	int ret = 0;

	dir = opendir(parser->dir);
	if (dir == NULL) {
		i_error("opendir(%s) failed: %m", parser->dir);
		return -1;
	}

	while ((d = readdir(dir)) != NULL) {
		if (d->d_name[0] == '.')
			continue;
		len = strlen(d->d_name);
		if (len >= 5 && strcmp(d->d_name + len - 5, ".mbox") == 0)
			continue;

		T_BEGIN {
			ret = test_parser_read_test(parser, d->d_name, &test);
		} T_END;
		if (ret < 0)
			break;
		if (ret > 0)
			array_append(&parser->tests, &test, 1);
	}
	if (closedir(dir) < 0) {
		i_error("closedir(%s) failed: %m", parser->dir);
		return -1;
	}
	return ret;
}

static struct imap_arg *test_parser_reply_init(pool_t pool, const char *atom)
{
	struct imap_arg *args;

	args = p_new(pool, struct imap_arg, 2);
	args[0].type = IMAP_ARG_ATOM;
	args[0]._data.str = p_strdup(pool, atom);
	args[1].type = IMAP_ARG_EOL;
	return args;
}

struct test_parser *test_parser_init(const char *dir)
{
	struct test_parser *parser;
	pool_t pool;

	pool = pool_alloconly_create("test parser", 1024*32);
	parser = p_new(pool, struct test_parser, 1);
	parser->pool = pool;
	parser->dir = p_strdup(pool, dir);
	parser->default_mbox_path =
		p_strdup_printf(pool, "%s/"DEFAULT_MBOX_FNAME, dir);
	i_array_init(&parser->tests, 128);

	parser->reply_ok = test_parser_reply_init(pool, "ok");
	parser->reply_no = test_parser_reply_init(pool, "no");
	parser->reply_bad = test_parser_reply_init(pool, "bad");

	if (test_parser_scan_dir(parser) < 0)
		i_fatal("Failed to read tests");
	return parser;
}

void test_parser_deinit(struct test_parser **_parser)
{
	struct test_parser *parser = *_parser;

	*_parser = NULL;
	array_free(&parser->tests);
	pool_unref(&parser->pool);
}

const ARRAY_TYPE(test) *test_parser_get_tests(struct test_parser *parser)
{
	return &parser->tests;
}
