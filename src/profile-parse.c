/* Copyright (c) 2013-2018 ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "istream.h"
#include "settings-parser.h"
#include "client-state.h"
#include "profile.h"

enum parser_state {
	STATE_ROOT,
	STATE_CLIENT,
	STATE_USER
};

struct profile_parser {
	struct profile *profile;
	enum parser_state state;
	unsigned int linenum;

	ARRAY_TYPE(profile_client) clients;
	ARRAY_TYPE(profile_user) users;

	struct setting_parser_context *cur_parser;
	unsigned int cur_count;
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct profile_client, name), NULL }

static const struct setting_define profile_client_setting_defines[] = {
    DEF(SET_STR, name),
    DEF(SET_ENUM, protocol),
    DEF(SET_UINT, connection_max_count),
    DEF(SET_BOOL, pop3_keep_mails),
    DEF(SET_BOOL, imap_idle),
    DEF(SET_STR, imap_fetch_immediate),
    DEF(SET_STR, imap_search_query),
    DEF(SET_STR, imap_fetch_manual),
    DEF(SET_TIME, imap_status_interval),
    DEF(SET_TIME, login_interval),
    DEF(SET_STR, imap_metadata_extension)
,
    SETTING_DEFINE_LIST_END};

const struct profile_client profile_client_default_settings = {
	.name = "",
	.protocol = "imap:pop3"
};

const struct setting_parser_info profile_client_setting_parser_info = {
	.defines = profile_client_setting_defines,
	.defaults = &profile_client_default_settings,

	.type_offset = offsetof(struct profile_client, name),
	.struct_size = sizeof(struct profile_client),

	.parent_offset = (size_t)-1
};

#undef DEF
#define DEF(type, name) \
	{ type, #name, offsetof(struct profile_user, name), NULL }

static const struct setting_define profile_user_setting_defines[] = {
    DEF(SET_STR, name),
    DEF(SET_STR, username_format),
    DEF(SET_UINT, user_count),
    DEF(SET_UINT, username_start_index),

    DEF(SET_TIME, mail_session_length),
    DEF(SET_TIME, mail_inbox_delivery_interval),
    DEF(SET_TIME, mail_spam_delivery_interval),
    DEF(SET_TIME, mail_send_interval),

    DEF(SET_UINT, mail_inbox_reply_percentage),
    DEF(SET_UINT, mail_inbox_delete_percentage),
    DEF(SET_UINT, mail_inbox_move_percentage),
    DEF(SET_UINT, mail_inbox_move_filter_percentage),
    DEF(SET_UINT, mail_inbox_search_percentage),

    DEF(SET_TIME, mail_action_delay),
    DEF(SET_TIME, mail_action_repeat_delay),
    DEF(SET_TIME, mail_write_duration),
    DEF(SET_SIZE, mail_write_size),

    SETTING_DEFINE_LIST_END};

const struct profile_user profile_user_default_settings = {
	.name = ""
};

const struct setting_parser_info profile_user_setting_parser_info = {
	.defines = profile_user_setting_defines,
	.defaults = &profile_user_default_settings,

	.type_offset = offsetof(struct profile_user, name),
	.struct_size = sizeof(struct profile_user),

	.parent_offset = (size_t)-1
};

#define IS_WHITE(c) ((c) == ' ' || (c) == '\t')

static char *line_remove_whitespace(char *line)
{
	unsigned int len;

	while (IS_WHITE(line[0])) line++;

	len = strlen(line);
	while (len > 0 && IS_WHITE(line[len-1])) len--;
	line[len] = '\0';
	return line;
}

static bool
try_parse_keyvalue(char *line, const char **key_r, const char **value_r)
{
	char *p, *p2;

	p = p2 = strchr(line, '=');
	if (p == NULL)
		return FALSE;
	while (p != line && IS_WHITE(p[-1])) p--;
	*p = '\0';
	p2++;
	while (IS_WHITE(p2[0])) p2++;

	*key_r = line;
	*value_r = p2;
	return TRUE;
}

static bool
try_parse_section(char *line, const char **key_r, const char **value_r)
{
	unsigned int len = strlen(line);
	char *p;

	if (len == 0 || line[len-1] != '{')
		return FALSE;
	*key_r = line;

	p = strchr(line, ' ');
	if (p != NULL) {
		*p++ = '\0';
		*value_r = p;
	} else {
		*value_r = "";
	}
	return TRUE;
}

static void parser_close(struct profile_parser *parser)
{
	struct profile_client *client;
	struct profile_user *user;

	switch (parser->state) {
	case STATE_ROOT:
		i_unreached();
	case STATE_CLIENT:
		client = settings_parser_get(parser->cur_parser);
		client->percentage = parser->cur_count;
		array_append(&parser->clients, &client, 1);
		break;
	case STATE_USER:
		user = settings_parser_get(parser->cur_parser);
		user->profile = parser->profile;
		user->percentage = parser->cur_count;
		array_append(&parser->users, &user, 1);
		break;
	}
	settings_parser_deinit(&parser->cur_parser);
	parser->state = STATE_ROOT;
	parser->cur_count = 0;
}

static void parser_add_client(struct profile_parser *parser)
{
	parser->state = STATE_CLIENT;
	parser->cur_parser = settings_parser_init(parser->profile->pool,
		&profile_client_setting_parser_info, 0);
}

static void parser_add_user(struct profile_parser *parser)
{
	struct profile_user *user;

	parser->state = STATE_USER;
	parser->cur_parser = settings_parser_init(parser->profile->pool,
		&profile_user_setting_parser_info, 0);

	/* set default */
	user = settings_parser_get(parser->cur_parser);
	user->username_start_index = 1;
}

static void profile_parse_line_root(struct profile_parser *parser, char *line)
{
	const char *key, *value, *nameline, *error;

	if (try_parse_keyvalue(line, &key, &value)) {
		if (strcmp(key, "total_user_count") == 0) {
			if (str_to_uint(value, &parser->profile->total_user_count) < 0) {
				i_fatal("Invalid setting %s at line %u: "
					"Invalid number '%s'",
					key, parser->linenum, value);
			}
		} else if (strcmp(key, "lmtp_port") == 0) {
			if (str_to_uint(value, &parser->profile->lmtp_port) < 0 ||
			    parser->profile->lmtp_port == 0 ||
			    parser->profile->lmtp_port > 65535) {
				i_fatal("Invalid setting %s at line %u: "
					"Invalid port number '%s'",
					key, parser->linenum, value);
			}
		} else if (strcmp(key, "lmtp_max_parallel_count") == 0) {
			if (str_to_uint(value, &parser->profile->lmtp_max_parallel_count) < 0) {
				i_fatal("Invalid setting %s at line %u: "
					"Invalid number",
					key, parser->linenum);
			}
		} else if (strcmp(key, "rampup_time") == 0) {
			if (settings_get_time(value, &parser->profile->rampup_time, &error) < 0) {
				i_fatal("Invalid setting %s at line %u: %s",
					key, parser->linenum, error);
			}
		} else {
			i_fatal("Unknown setting at line %u: %s", parser->linenum, key);
		}
		return;
	}

	if (!try_parse_section(line, &key, &value))
		i_fatal("Invalid data at line %u: %s", parser->linenum, line);
	if (strcmp(key, "client") == 0)
		parser_add_client(parser);
	else if (strcmp(key, "user") == 0)
		parser_add_user(parser);
	else
		i_fatal("Unknown section at line %u: %s", parser->linenum, key);

	if (value[0] != '\0') {
		nameline = t_strdup_printf("name=%s", value);
		if (settings_parse_line(parser->cur_parser, nameline) != 1)
			i_unreached();
	}
}

static void parse_count(struct profile_parser *parser, const char *value,
			unsigned int *count_r)
{
	const char *p;

	p = strchr(value, '%');
	if (p == NULL || p[1] != '\0') {
		i_fatal("Invalid count setting at line %u: "
			"Only nn%% values are supported currently",
			parser->linenum);
	}
	value = t_strdup_until(value, p);
	if (str_to_uint(value, count_r) < 0) {
		i_fatal("Invalid count setting at line %u: Invalid number '%s'",
			parser->linenum, value);
	}
	if (*count_r > 100) {
		i_fatal("Invalid count setting at line %u: "
			"Value can't be more than 100%%", parser->linenum);
	}
}

static void
profile_parse_line_section(struct profile_parser *parser, char *line)
{
	const char *key, *value, *newline;
	int ret;

	if (strcmp(line, "}") == 0) {
		parser_close(parser);
		return;
	}

	if (!try_parse_keyvalue(line, &key, &value))
		i_fatal("Invalid data at line %u: %s", parser->linenum, line);

	newline = t_strdup_printf("%s=%s", key, value);
	if (strcmp(key, "count") == 0)
		parse_count(parser, value, &parser->cur_count);
	else if ((ret = settings_parse_line(parser->cur_parser, newline)) < 0) {
		i_fatal("Invalid value for setting '%s' at line %u: %s",
			key, parser->linenum, value);
	} else if (ret == 0) {
		i_fatal("Unknown setting at line %u: %s", parser->linenum, key);
	}
}

static void profile_finish(struct profile_parser *parser)
{
	struct profile_client *const *clientp;
	struct profile_user *const *userp;
	unsigned int percentage_count;

	if (parser->profile->lmtp_port == 0)
		i_fatal("lmtp_port setting missing");
	if (parser->profile->total_user_count == 0)
		i_fatal("total_user_count setting missing");
	if (array_count(&parser->clients) == 0)
		i_fatal("No client {} sections defined");
	if (array_count(&parser->users) == 0)
		i_fatal("No user {} sections defined");

	percentage_count = 0;
	array_foreach(&parser->clients, clientp)
		percentage_count += (*clientp)->percentage;
	if (percentage_count < 100)
		i_fatal("client { count } total must be at least 100%% (now is %u%%)", percentage_count);

	percentage_count = 0;
	array_foreach(&parser->users, userp) {
		if ((*userp)->username_format == NULL)
			i_fatal("username_format not set");
		(*userp)->user_count = parser->profile->total_user_count *
			(*userp)->percentage / 100;
		percentage_count += (*userp)->percentage;
	}
	if (percentage_count != 100)
		i_fatal("user { count } total doesn't equal 100%% (but %u%%)", percentage_count);

	parser->profile->users = parser->users;
	parser->profile->clients = parser->clients;
}

struct profile *profile_parse(const char *path)
{
	struct profile *profile;
	struct profile_parser parser;
	pool_t pool = pool_alloconly_create("profile", 1024*16);
	struct istream *input;
	char *line;

	profile = p_new(pool, struct profile, 1);
	profile->pool = pool;
	profile->path = p_strdup(pool, path);

	i_zero(&parser);
	parser.profile = profile;
	p_array_init(&parser.clients, pool, 4);
	p_array_init(&parser.users, pool, 4);

	input = i_stream_create_file(path, (size_t)-1);
	while ((line = i_stream_read_next_line(input)) != NULL) T_BEGIN {
		parser.linenum++;
		line = line_remove_whitespace(line);
		if (line[0] == '\0' || line[0] == '#')
			;
		else switch (parser.state) {
		case STATE_ROOT:
			profile_parse_line_root(&parser, line);
			break;
		case STATE_CLIENT:
			profile_parse_line_section(&parser, line);
			break;
		case STATE_USER:
			profile_parse_line_section(&parser, line);
			break;
		}
	} T_END;
	if (input->stream_errno != 0)
		i_fatal("read(%s) failed: %s", path, i_stream_get_error(input));
	i_stream_destroy(&input);

	profile_finish(&parser);
	states[STATE_LMTP].probability = 100;
	states[STATE_GET_METADATA].probability = 100;
	return profile;
}
