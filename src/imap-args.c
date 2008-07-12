/* Copyright (c) 2007-2008 Timo Sirainen */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "imap-parser.h"
#include "imap-args.h"

static void
imap_args_to_str_dest(const struct imap_arg *args, string_t *str)
{
	const ARRAY_TYPE(imap_arg_list) *list;
	bool first = TRUE;

	for (; args->type != IMAP_ARG_EOL; args++) {
		if (first)
			first = FALSE;
		else
			str_append_c(str, ' ');

		switch (args->type) {
		case IMAP_ARG_NIL:
			str_append(str, "NIL");
			break;
		case IMAP_ARG_ATOM:
			str_append(str, IMAP_ARG_STR(args));
			break;
		case IMAP_ARG_STRING:
			str_append_c(str, '"');
			str_append(str, str_escape(IMAP_ARG_STR(args)));
			str_append_c(str, '"');
			break;
		case IMAP_ARG_LITERAL: {
			const char *strarg = IMAP_ARG_STR(args);
			str_printfa(str, "{%"PRIuSIZE_T"}\r\n", strlen(strarg));
			str_append(str, strarg);
			break;
		}
		case IMAP_ARG_LIST:
			str_append_c(str, '(');
			list = IMAP_ARG_LIST(args);
			imap_args_to_str_dest(array_idx(list, 0), str);
			str_append_c(str, ')');
			break;
		case IMAP_ARG_LITERAL_SIZE:
		case IMAP_ARG_LITERAL_SIZE_NONSYNC:
			str_printfa(str, "{%"PRIuUOFF_T"}\r\n",
				    IMAP_ARG_LITERAL_SIZE(args));
			str_append(str, "<too large>");
			break;
		case IMAP_ARG_EOL:
			i_unreached();
		}
	}
}

const char *imap_args_to_str(const struct imap_arg *args)
{
	string_t *str;

	if (args == NULL)
		return "";

	str = t_str_new(256);
	imap_args_to_str_dest(args, str);
	return str_c(str);
}
