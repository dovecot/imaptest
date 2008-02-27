/* Copyright (C) 2007 Timo Sirainen */

#include "lib.h"
#include "array.h"
#include "mail-types.h"

#include "settings.h"
#include "mailbox.h"
#include "client.h"
#include "checkpoint.h"

#include <stdlib.h>

struct mailbox_checkpoint_context {
	unsigned int clients_left;
	unsigned int check_sent:1;
};

struct checkpoint_context {
	struct message_metadata_dynamic *messages;
	ARRAY_DEFINE(all_keywords, const char *);
	ARRAY_DEFINE(cur_keywords_map, unsigned int);
	uint32_t *uids;
	unsigned int *flag_counts;
	unsigned int count;

	unsigned int first:1;
	unsigned int errors:1;
};

static void
keyword_map_update(struct checkpoint_context *ctx, struct client *client)
{
	const struct mailbox_keyword *kw_my;
	const char *const *kw_all, *name;
	unsigned int i, j, my_count, all_count;

	array_clear(&ctx->cur_keywords_map);
	kw_my = array_get(&client->view->keywords, &my_count);
	kw_all = array_get(&ctx->all_keywords, &all_count);
	for (i = 0; i < my_count; i++) {
		for (j = 0; j < all_count; j++) {
			if (strcasecmp(kw_all[j], kw_my[i].name->name) == 0)
				break;
		}

		array_append(&ctx->cur_keywords_map, &j, 1);
		if (j == all_count) {
			name = kw_my[i].name->name;
			if (!ctx->first) {
				i_error("Checkpoint: client %u: "
					"Missing keyword %s",
					client->idx, name);
			}
			array_append(&ctx->all_keywords, &name, 1);
			kw_all = array_get(&ctx->all_keywords, &all_count);
		}
	}
}

static void keywords_remap(struct checkpoint_context *ctx,
			   const uint8_t *src, uint8_t *dest,
			   unsigned int dest_size)
{
	const unsigned int *kw_map;
	unsigned int i, count;

	memset(dest, 0, dest_size);

	kw_map = array_get(&ctx->cur_keywords_map, &count);
	for (i = 0; i < count; i++) {
		if ((src[i/8] & (1 << (i%8))) != 0)
			dest[kw_map[i]/8] |= 1 << (kw_map[i]%8);
	}
}

static void
checkpoint_update(struct checkpoint_context *ctx, struct client *client)
{
	struct mailbox_view *view = client->view;
	const struct message_metadata_dynamic *msgs;
	const uint32_t *uids;
	uint8_t *keywords_remapped;
	enum mail_flags this_flags, other_flags;
	unsigned int i, count, dest_keywords_size;

	keyword_map_update(ctx, client);

	uids = array_get(&view->uidmap, &count);
	if (count != ctx->count) {
		ctx->errors = TRUE;
		i_error("Checkpoint: client %u: "
			"Mailbox has only %u of %u messages",
			client->global_id, count, ctx->count);
	}

	msgs = array_get(&view->messages, &count);
	dest_keywords_size = (array_count(&ctx->all_keywords) + 7) / 8;
	keywords_remapped = dest_keywords_size == 0 ? NULL :
		t_malloc(dest_keywords_size);
	for (i = 0; i < count; i++) {
		if (uids[i] == 0) {
			/* we don't have this message's metadata */
			continue;
		}
		if (ctx->uids[i] == 0)
			ctx->uids[i] = uids[i];
		if (uids[i] != ctx->uids[i]) {
			ctx->errors = TRUE;
			i_error("Checkpoint: client %u: "
				"Message seq=%u UID %u != %u",
				client->global_id, i + 1,
				uids[i], ctx->uids[i]);
			break;
		}

		if ((msgs[i].mail_flags & MAIL_FLAGS_SET) == 0)
			continue;

		keywords_remap(ctx, msgs[i].keyword_bitmask,
			       keywords_remapped, dest_keywords_size);
		ctx->flag_counts[i]++;
		if ((ctx->messages[i].mail_flags & MAIL_FLAGS_SET) == 0) {
			/* first one to set flags */
			ctx->messages[i].mail_flags = msgs[i].mail_flags;
			ctx->messages[i].keyword_bitmask =
				i_malloc(dest_keywords_size);
			memcpy(ctx->messages[i].keyword_bitmask,
			       keywords_remapped, dest_keywords_size);
			continue;
		}

		if ((msgs[i].mail_flags & MAIL_RECENT) != 0 &&
		    !view->storage->dont_track_recent) {
			if ((ctx->messages[i].mail_flags & MAIL_RECENT) == 0)
				ctx->messages[i].mail_flags |= MAIL_RECENT;
			else {
				i_error("Checkpoint: client %u: "
					"Message seq=%u UID=%u "
					"has \\Recent flag in multiple sessions",
					client->global_id, i + 1, uids[i]);
				view->storage->dont_track_recent = TRUE;
			}
		}

		this_flags = msgs[i].mail_flags & ~MAIL_RECENT;
		other_flags = ctx->messages[i].mail_flags & ~MAIL_RECENT;
		if (this_flags != other_flags) {
			ctx->errors = TRUE;
			i_error("Checkpoint: client %u: Message seq=%u UID=%u "
				"flags differ: (%s) vs (%s)",
				client->global_id, i + 1, uids[i],
				mail_flags_to_str(this_flags),
				mail_flags_to_str(other_flags));
		}
		if (memcmp(keywords_remapped, ctx->messages[i].keyword_bitmask,
			   dest_keywords_size) != 0) {
			ctx->errors = TRUE;
			i_error("Checkpoint: client %u: Message seq=%u UID=%u "
				"keywords differ: (%s) vs (%s)",
				client->global_id, i + 1, uids[i],
				mailbox_view_keywords_to_str(view, msgs[i].keyword_bitmask),
				mailbox_view_keywords_to_str(view, ctx->messages[i].keyword_bitmask));
		}
	}
}

static void checkpoint_check_missing_recent(struct checkpoint_context *ctx,
					    unsigned int min_uidnext)
{
	unsigned int i, client_count = array_count(&clients);

	/* find the first message that we know were created by ourself */
	for (i = 0; i < ctx->count; i++) {
		if (ctx->uids[i] > min_uidnext)
			break;
	}

	/* make sure \Recent flag is found from all of them */
	for (; i < ctx->count; i++) {
		if (ctx->flag_counts[i] != client_count ||
		    (ctx->messages[i].mail_flags & MAIL_FLAGS_SET) == 0)
			continue;
		if ((ctx->messages[i].mail_flags & MAIL_RECENT) == 0) {
			i_error("Checkpoint: Message seq=%u UID=%u "
				"isn't \\Recent anywhere", i + 1, ctx->uids[i]);
		}
	}
}

void checkpoint_neg(struct mailbox_storage *storage)
{
	struct checkpoint_context ctx;
	struct client *const *c;
	unsigned int min_uidnext = -1U, max_msgs_count = 0;
	unsigned int i, count, check_count = 0;
	unsigned int recent_total;
	bool orig_dont_track_recent = storage->dont_track_recent;

	i_assert(storage->checkpoint->clients_left > 0);
	if (--storage->checkpoint->clients_left > 0)
		return;

	c = array_get(&clients, &count);

	if (!storage->checkpoint->check_sent) {
		/* everyone's finally finished their commands. now send CHECK
		   to make sure everyone sees each others' changes */
		for (i = 0; i < count; i++) {
			if (c[i] == NULL || c[i]->checkpointing != storage)
				continue;

			/* send the checkpoint command */
			c[i]->plan[0] = STATE_CHECK;
			c[i]->plan_size = 1;
			(void)client_send_next_cmd(c[i]);
			storage->checkpoint->clients_left++;
		}
		if (storage->checkpoint->clients_left == 0) {
			/* there are no clients to checkpoint anymore */
			i_free_and_null(storage->checkpoint);
			return;
		}
		storage->checkpoint->check_sent = TRUE;
		return;
	}

	/* get maximum number of messages in mailbox */
	recent_total = 0;
	for (i = 0; i < count; i++) {
		if (c[i] == NULL || c[i]->checkpointing != storage)
			continue;

		i_assert(array_count(&c[i]->commands) == 0);
		if (c[i]->view->select_uidnext != 0) {
			min_uidnext = I_MIN(min_uidnext,
					    c[i]->view->select_uidnext);
		}
		recent_total += c[i]->view->recent_count;
		max_msgs_count = I_MAX(max_msgs_count,
				       array_count(&c[i]->view->uidmap));
	}

	/* make sure everyone has the same idea of what the mailbox
	   looks like */
	memset(&ctx, 0, sizeof(ctx));
	if (max_msgs_count > 0) {
		ctx.count = max_msgs_count;
		ctx.messages = i_new(struct message_metadata_dynamic,
				     ctx.count);
		ctx.uids = i_new(uint32_t, ctx.count);
		ctx.flag_counts = i_new(uint32_t, ctx.count);
		ctx.first = TRUE;
		i_array_init(&ctx.all_keywords, 32);
		i_array_init(&ctx.cur_keywords_map, 32);
		for (i = 0; i < count; i++) {
			if (c[i] == NULL || c[i]->checkpointing != storage)
				continue;

			check_count++;
			checkpoint_update(&ctx, c[i]);
			ctx.first = FALSE;
		}
		for (i = 0; i < ctx.count; i++)
			i_free(ctx.messages[i].keyword_bitmask);

		if (total_disconnects == 0 && min_uidnext != 0 &&
		    !storage->dont_track_recent) {
			/* this only works if no clients have disconnected */
			checkpoint_check_missing_recent(&ctx, min_uidnext);
		}

		if (!storage->seen_all_recent || storage->dont_track_recent) {
			/* can't handle this */
		} else if (recent_total > ctx.count) {
			i_error("Checkpoint: Total RECENT count %u "
				"larger than current message count %u",
				recent_total, ctx.count);
			storage->dont_track_recent = TRUE;
		} else if (total_disconnects == 0 &&
			   recent_total != ctx.count) {
			i_error("Checkpoint: Total RECENT count %u != %u",
				recent_total, ctx.count);
			storage->dont_track_recent = TRUE;
		}
		array_free(&ctx.all_keywords);
		array_free(&ctx.cur_keywords_map);
		i_free(ctx.flag_counts);
		i_free(ctx.uids);
		i_free(ctx.messages);
	}
	if (!ctx.errors)
		counters[STATE_CHECKPOINT] += check_count;
	if (conf.error_quit && (ctx.errors || storage->dont_track_recent))
		exit(2);

	for (i = 0; i < count; i++) {
		if (c[i] == NULL)
			continue;
		if (c[i]->checkpointing == storage)
			c[i]->checkpointing = NULL;

		if (array_count(&c[i]->commands) == 0 &&
		    c[i]->state != STATE_BANNER) {
			(void)client_send_more_commands(c[i]);
			i_assert(array_count(&c[i]->commands) > 0);
		}
	}

	if (storage->dont_track_recent && !orig_dont_track_recent)
		i_warning("Disabling \\Recent flag tracking");

	i_free_and_null(storage->checkpoint);
}

void clients_checkpoint(struct mailbox_storage *storage)
{
	struct client *const *c;
	unsigned int i, count;

	if (storage->checkpoint != NULL)
		return;

	storage->checkpoint = i_new(struct mailbox_checkpoint_context, 1);

	c = array_get(&clients, &count);
	for (i = 0; i < count; i++) {
		if (c[i] == NULL || c[i]->login_state != LSTATE_SELECTED)
			continue;

		if (c[i]->view->storage == storage) {
			c[i]->checkpointing = storage;
			if (array_count(&c[i]->commands) > 0)
				storage->checkpoint->clients_left++;
		}
	}
	if (storage->checkpoint->clients_left == 0) {
		storage->checkpoint->clients_left++;
		checkpoint_neg(storage);
	}
}
