/* Copyright (C) 2008 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "utc-mktime.h"
#include "imap-date.h"
#include "imap-parser.h"
#include "commands.h"
#include "mailbox.h"
#include "client.h"
#include "search.h"

#include <time.h>
#include <stdlib.h>

enum search_arg_type {
	SEARCH_OR,
	SEARCH_SUB,

	/* sequence sets */
	SEARCH_ALL,
	SEARCH_SEQSET,

	/* size */
	SEARCH_SMALLER,
	SEARCH_LARGER,

	/* date */
	SEARCH_BEFORE,
	SEARCH_ON,
	SEARCH_SINCE,

	SEARCH_TYPE_COUNT
};

struct search_node {
	enum search_arg_type type;

	/* for AND/ORs */
	struct search_node *first_child, *next_sibling;
	ARRAY_TYPE(seq_range) seqset;
	const char *str;
	uoff_t size;
	time_t date;
};

struct search_context {
	pool_t pool;
	struct search_node root;
	ARRAY_TYPE(seq_range) result;
};

static int
search_node_verify_msg(struct search_node *node,
		       const struct message_metadata_static *ms)
{
	time_t t;

	switch (node->type) {
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
		if (ms->msg == NULL || ms->msg->full_size == 0)
			break;
		if (node->type == SEARCH_SMALLER)
			return ms->msg->full_size < node->size;
		else
			return ms->msg->full_size > node->size;
		break;
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		if (ms->internaldate == 0)
			break;
		t = ms->internaldate + ms->internaldate_tz*60;
		switch (node->type) {
		case SEARCH_BEFORE:
			return t < node->date;
		case SEARCH_ON:
			return t >= node->date && t < node->date + 3600*24;
		case SEARCH_SINCE:
			return t >= node->date;
		default:
			i_unreached();
		}
	case SEARCH_OR:
	case SEARCH_SUB:
	case SEARCH_ALL:
	case SEARCH_SEQSET:
	case SEARCH_TYPE_COUNT:
		i_unreached();
	}
	return -1;
}

static int
search_node_verify(struct client *client, struct search_node *node,
		   uint32_t seq, bool parent_or)
{
	const struct message_metadata_static *ms;
	int ret = -1, ret2;

	switch (node->type) {
	case SEARCH_OR:
	case SEARCH_SUB:
		ret = search_node_verify(client, node->first_child, seq,
					 node->type == SEARCH_OR);
		break;
	case SEARCH_ALL:
		ret = 1;
		break;
	case SEARCH_SEQSET:
		ret = seq_range_exists(&node->seqset, seq);
		break;
	default:
		ms = message_metadata_static_lookup_seq(client->view, seq);
		if (ms != NULL)
			ret = search_node_verify_msg(node, ms);
		break;
	}

	if (ret == 0 && !parent_or)
		return 0;
	if (ret > 0 && parent_or)
		return 1;

	if (node->next_sibling == NULL)
		return ret;
	ret2 = search_node_verify(client, node->next_sibling, seq, parent_or);
	if (parent_or) {
		if (ret == -1 && ret2 == 0)
			ret2 = -1;
	} else {
		if (ret == -1 && ret2 > 0)
			ret2 = -1;
	}
	return ret2;
}

static void search_verify_result(struct client *client)
{
	struct search_context *ctx = client->search_ctx;
	const uint32_t *uids;
	uint32_t seq, msgs;
	int ret;
	bool found;

	uids = array_get(&client->view->uidmap, &msgs);
	for (seq = 1; seq <= msgs; seq++) {
		ret = search_node_verify(client, &ctx->root, seq, FALSE);
		found = seq_range_exists(&ctx->result, seq);
		if (ret > 0 && !found) {
			client_input_error(client,
				"SEARCH result missing seq %u (uid %u)",
				seq, uids[seq-1]);
		} else if (ret == 0 && found) {
			client_input_error(client,
				"SEARCH result has extra seq %u (uid %u)",
				seq, uids[seq-1]);
		}
	}
}

static void search_callback(struct client *client, struct command *cmd,
			    const struct imap_arg *args ATTR_UNUSED,
			    enum command_reply reply)
{
	i_assert(client->search_ctx != NULL);

	if (reply != REPLY_OK)
		client_input_error(client, "SEARCH failed");
	else if (!array_is_created(&client->search_ctx->result))
		client_input_error(client, "Missing untagged SEARCH");
	else {
		counters[cmd->state]++;
		search_verify_result(client);
	}
	pool_unref(&client->search_ctx->pool);
	client->search_ctx = NULL;
}

static time_t time_truncate_to_day(time_t t)
{
	const struct tm *tm;
	struct tm day_tm;

	tm = gmtime(&t);
	day_tm = *tm;
	day_tm.tm_hour = 0;
	day_tm.tm_min = 0;
	day_tm.tm_sec = 0;
	day_tm.tm_isdst = -1;
	return utc_mktime(&day_tm);
}

static struct search_node *
search_command_build(struct client *client, int probability)
{
	pool_t pool = client->search_ctx->pool;
	struct message_metadata_static *const *ms, *m1 = NULL, *m2 = NULL;
	struct search_node *node;
	unsigned int i, msgs, ms_count;

	if ((rand() % 100) >= probability)
		return NULL;

	ms = array_get(&client->view->storage->static_metadata, &ms_count);
	node = p_new(pool, struct search_node, 1);
again:
	node->type = rand() % SEARCH_TYPE_COUNT;
	switch (node->type) {
	case SEARCH_OR:
	case SEARCH_SUB:
		probability -= I_MAX(probability/30, 1);
		node->first_child = search_command_build(client, probability);
		if (node->first_child == NULL)
			goto again;
		break;
	case SEARCH_SEQSET:
		p_array_init(&node->seqset, pool, 5);
		msgs = array_count(&client->view->uidmap);
		if (!client_get_random_seq_range(client, &node->seqset,
						 msgs / 2 + 1,
						 CLIENT_RANDOM_FLAG_TYPE_NONE))
			node->type = SEARCH_ALL;
		break;
	case SEARCH_ALL:
		break;
	case SEARCH_SMALLER:
	case SEARCH_LARGER:
		/* find two messages with known sizes and use their average */
		for (i = 0; i < ms_count; i++) {
			if (ms[i]->msg != NULL && ms[i]->msg->full_size != 0) {
				if (m1 == NULL)
					m1 = ms[i];
				else {
					m2 = ms[i];
					break;
				}
			}
		}
		if (m2 != NULL) {
			node->size = (m1->msg->full_size +
				      m2->msg->full_size) / 2;
		}
		if (node->size == 0)
			node->size = 2048 + (rand() % 2048);
		break;
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		/* find two messages with known internalsizes and use their
		   average */
		for (i = 0; i < ms_count; i++) {
			if (ms[i]->internaldate != 0) {
				if (m1 == NULL)
					m1 = ms[i];
				else {
					m2 = ms[i];
					break;
				}
			}
		}
		if (m2 != NULL)
			node->date = (m1->internaldate + m2->internaldate) / 2;
		if (node->date == 0)
			node->date = time(NULL) - (3600*24 * (rand() % 10));
		node->date = time_truncate_to_day(node->date);
		break;
	case SEARCH_TYPE_COUNT:
		i_unreached();
	}

	probability /= 2;
	node->next_sibling = search_command_build(client, probability);
	return node;
}

static void search_command_append(string_t *cmd, const struct search_node *node)
{
	const struct search_node *left, *right;
	unsigned int len;

	switch (node->type) {
	case SEARCH_OR:
		i_assert(node->first_child != NULL);
		left = node->first_child;
		right = left->next_sibling;

		str_append_c(cmd, '(');
		while (right != NULL) {
			str_append(cmd, "OR ");
			search_command_append(cmd, left);
			str_append_c(cmd, ' ');
			left = right;
			right = right->next_sibling;
		}
		search_command_append(cmd, left);
		str_append_c(cmd, ')');
		break;
	case SEARCH_SUB:
		i_assert(node->first_child != NULL);
		str_append(cmd, "(");
		node = node->first_child;
		while (node != NULL) {
			search_command_append(cmd, node);
			str_append_c(cmd, ' ');
			node = node->next_sibling;
		}
		str_truncate(cmd, str_len(cmd)-1);
		str_append_c(cmd, ')');
		break;
	case SEARCH_ALL:
		str_append(cmd, "ALL");
		break;
	case SEARCH_SEQSET: {
		const struct seq_range *range;
		unsigned int i, count;

		range = array_get(&node->seqset, &count);
		for (i = 0; i < count; i++) {
			if (i > 0)
				str_append_c(cmd, ',');
			if (range[i].seq1 == range[i].seq2)
				str_printfa(cmd, "%u", range[i].seq1);
			else {
				str_printfa(cmd, "%u:%u", range[i].seq1,
					    range[i].seq2);
			}
		}
		break;
	}
	case SEARCH_SMALLER:
		str_printfa(cmd, "SMALLER %"PRIuUOFF_T, node->size);
		break;
	case SEARCH_LARGER:
		str_printfa(cmd, "LARGER %"PRIuUOFF_T, node->size);
		break;
	case SEARCH_BEFORE:
	case SEARCH_ON:
	case SEARCH_SINCE:
		if (node->type == SEARCH_BEFORE)
			str_append(cmd, "BEFORE");
		else if (node->type == SEARCH_ON)
			str_append(cmd, "ON");
		else
			str_append(cmd, "SINCE");
		str_append_c(cmd, ' ');
		len = str_len(cmd);
		str_append(cmd, imap_to_datetime(node->date));
		/* truncate to contain only date */
		str_truncate(cmd, len + 11);
		break;
	case SEARCH_TYPE_COUNT:
		i_unreached();
	}
}

void search_command_send(struct client *client)
{
	pool_t pool;
	string_t *cmd;

	i_assert(client->search_ctx == NULL);

	pool = pool_alloconly_create("search context", 16384);
	client->search_ctx = p_new(pool, struct search_context, 1);
	client->search_ctx->pool = pool;
	client->search_ctx->root.type = SEARCH_SUB;
	client->search_ctx->root.first_child =
		search_command_build(client, 100);

	cmd = t_str_new(256);
	str_append(cmd, "SEARCH ");
	search_command_append(cmd, &client->search_ctx->root);
	if (rand() % 2 == 0) {
		/* remove () around the search query */
		str_delete(cmd, 7, 1);
		str_truncate(cmd, str_len(cmd)-1);
	}
	command_send(client, str_c(cmd), search_callback);
}

void search_result(struct client *client, const struct imap_arg *args)
{
	const char *str;
	unsigned long num;
	unsigned int msgs_count;

	if (client->search_ctx == NULL) {
		client_input_error(client, "unexpected SEARCH reply");
		return;
	}

	if (array_is_created(&client->search_ctx->result)) {
		client_input_error(client, "duplicate SEARCH reply");
		return;
	}

	msgs_count = array_count(&client->view->uidmap);
	p_array_init(&client->search_ctx->result, client->search_ctx->pool, 64);
	for (; args->type != IMAP_ARG_EOL; args++) {
		if (args->type != IMAP_ARG_ATOM) {
			client_input_error(client,
					   "SEARCH reply contains non-atoms");
			return;
		}
		str = IMAP_ARG_STR(args);
		num = strtoul(str, NULL, 10);
		if (!is_numeric(str, '\0') || num == 0 || num > (uint32_t)-1) {
			client_input_error(client,
				"SEARCH reply contains invalid numbers");
			return;
		}
		if (num > msgs_count) {
			client_input_error(client,
					   "SEARCH reply seq %lu > %u EXISTS",
					   num, msgs_count);
			break;
		}
		seq_range_array_add(&client->search_ctx->result, 0, num);
	}
}
