#ifndef MAILBOX_H
#define MAILBOX_H

#include "seq-range-array.h"
#include "mail-types.h"

struct message_header {
	const char *name;
	const unsigned char *value;
	unsigned int value_len;
	bool missing:1;
};
ARRAY_DEFINE_TYPE(message_header, struct message_header);

struct message_global {
	char *message_id;
	const char *body, *bodystructure, *envelope;
	uoff_t header_size, body_size, full_size, mime1_size;

	/* parsed fields: */
	const char *subject_utf8_tcase;
	time_t sent_date;
	int sent_date_tz;

	ARRAY_TYPE(message_header) headers;
#define MSG_MAX_BODY_WORDS 16
	/* some random words from message body */
	ARRAY(const char *) body_words;
};

struct fetch_metadata {
  char* key;
  char* value;
};

ARRAY_DEFINE_TYPE( fetch_metadata, struct fetch_metadata);

struct message_metadata_static {
	uint32_t uid;
	unsigned int refcount;
  /* seq -> uid */
  ARRAY_TYPE( fetch_metadata) fetch_m;
	/* timestamp when this message should be removed if it still has
	   refcount=0 */
	time_t ref0_timeout;

	time_t internaldate;
	int internaldate_tz;
	unsigned int owner_client_idx1;
	/* If non-zero, specifies the client that saw the message as \Recent
	   with a read-write mailbox. */
	unsigned int recent_client_global_id;

	struct message_global *msg;

	bool expunged:1;
};

enum flagchange_dirty_type {
	FLAGCHANGE_DIRTY_NO = 0,
	/* We've sent at least one STORE command but haven't yet received any
	   FETCH replies for it */
	FLAGCHANGE_DIRTY_YES,
	/* We've received a FETCH reply, but there are multiple commands in
	   progress so we're most likely going to be receiving more FETCH
	   replies */
	FLAGCHANGE_DIRTY_WAITING,
	/* There's only one command in progress and we've received a FETCH
	   reply from it. However it's possible that it was actually an
	   unsolicited reply from server, and the actual expected FETCH reply
	   is still coming. */
	FLAGCHANGE_DIRTY_MAYBE
};

struct message_metadata_dynamic {
#define MAIL_FLAGS_SET 0x40000000
	uint64_t modseq;
	/* flags and keywords are set only if MAIL_FLAGS_SET is set */
	enum mail_flags mail_flags;
	uint8_t *keyword_bitmask; /* [view->keyword_bitmask_alloc_size] */

	struct message_metadata_static *ms;
	/* Number of commands currently expected to return FETCH FLAGS for
	   this message. STORE +SILENT also increments this so dirtyness gets
	   handled right. */
	unsigned int fetch_refcount;

	enum flagchange_dirty_type flagchange_dirty_type;
};
ARRAY_DEFINE_TYPE(message_metadata_dynamic, struct message_metadata_dynamic);

struct mailbox_keyword_name {
	char *name;
	unsigned int owner_client_idx1;

	bool seen_nonpermanent:1;
};

struct mailbox_keyword {
	struct mailbox_keyword_name *name;

	/* number of messages containing this keyword (that we know of) */
	unsigned int msg_refcount;
	unsigned int flags_counter; /* should match view->flags_counter */

	bool permanent:1;
};
ARRAY_DEFINE_TYPE(mailbox_keyword, struct mailbox_keyword);

struct mailbox_offline_cache {
	struct mailbox_storage *storage;
	int refcount;

	unsigned int uidvalidity;
	uint64_t highest_modseq;

	/* all keywords used currently in a mailbox */
	ARRAY(struct mailbox_keyword_name *) keywords;
	/* seq -> uid */
	ARRAY(uint32_t) uidmap;
	/* seq -> metadata */
	ARRAY_TYPE(message_metadata_dynamic) messages;
};

struct mailbox_storage {
	struct mailbox_source *source;
	int refcount;
	char *guid;
	char *name;

	struct mailbox_checkpoint_context *checkpoint;

	/* we assume that uidvalidity doesn't change while imaptest
	   is running */
	unsigned int uidvalidity;

	/* Exported mailbox state for resyncing with QRESYNC extension.
	   This is (sometimes) updated when mailbox is being closed or
	   client gets disconnected. */
	struct mailbox_offline_cache *cache;

	/* Number of messages in static_metadata with refcount=0 */
	unsigned int static_metadata_ref0_count;
	/* Timestamp when static_metadata should next be scanned for
	   removal of old refcount=0 messages */
	time_t static_metadata_ref0_next_scan;

	/* static metadata for this mailbox. sorted by UID. */
	ARRAY(struct message_metadata_static *) static_metadata;
	ARRAY(struct mailbox_keyword_name *) keyword_names;
	/* List of UIDs that are definitely expunged. May contain UIDs that
	   have never even existed. */
	ARRAY_TYPE(seq_range) expunged_uids;

#define MAIL_FLAGS_OWN_COUNT 5
#define MAIL_FLAG_DELETED_IDX 2
	unsigned int flags_owner_client_idx1[MAIL_FLAGS_OWN_COUNT];

	bool assign_msg_owners:1;
	bool assign_flag_owners:1;
	bool flag_owner_clients_assigned:1;
	bool seen_all_recent:1;
	bool dont_track_recent:1;
};

struct mailbox_view {
	struct mailbox_storage *storage;
	unsigned int keyword_bitmask_alloc_size;
	unsigned int flags_counter;
	unsigned int recent_count;
	unsigned int select_uidnext; /* UIDNEXT received on SELECT */
    uint64_t highest_modseq;
	char *last_thread_reply;

	/* all keywords used currently in a mailbox */
	ARRAY_TYPE(mailbox_keyword) keywords;

	/* seq -> uid */
	ARRAY(uint32_t) uidmap;
	/* seq -> metadata */
	ARRAY_TYPE(message_metadata_dynamic) messages;
	/* number of non-zero UIDs in uidmap. */
	unsigned int known_uid_count;

	bool readwrite:1;
	bool keywords_can_create_more:1;
};

HASH_TABLE_DEFINE_TYPE(mailbox_storage, char *, struct mailbox_storage *);

extern HASH_TABLE_TYPE(mailbox_storage) storages;
extern const char *mail_flag_names[]; /* enum mail_flags names */

struct mailbox_storage *
mailbox_storage_lookup(struct mailbox_source *source, const char *username,
		       const char *mailbox);
struct mailbox_storage *
mailbox_storage_get(struct mailbox_source *source, const char *username,
		    const char *mailbox);
void mailbox_storage_unref(struct mailbox_storage **storage);
void mailbox_storage_reset(struct mailbox_storage *storage);

struct mailbox_view *mailbox_view_new(struct mailbox_storage *storage);
void mailbox_view_free(struct mailbox_view **_mailbox);

bool mailbox_view_save_offline_cache(struct mailbox_view *view);
void mailbox_view_restore_offline_cache(struct mailbox_view *view,
					struct mailbox_offline_cache *cache);
void mailbox_offline_cache_unref(struct mailbox_offline_cache **cache);

bool mailbox_view_keyword_find(struct mailbox_view *view, const char *name,
			       unsigned int *idx_r);
struct mailbox_keyword *mailbox_view_keyword_get(struct mailbox_view *view,
						 unsigned int idx);
struct mailbox_keyword *
mailbox_view_keyword_get_by_name(struct mailbox_view *view,
				 const char *name);
void mailbox_view_keyword_add(struct mailbox_view *view, const char *name);
void mailbox_keywords_clear(struct mailbox_view *view,
			    struct message_metadata_dynamic *metadata);
void mailbox_view_keywords_realloc(struct mailbox_view *view,
				   unsigned int new_alloc_size);

enum mail_flags mail_flag_parse(const char *str);
const char *mail_flags_to_str(enum mail_flags flags);
void mailbox_view_keywords_write(struct mailbox_view *view,
				 const uint8_t *bitmask, string_t *str);
const char *mailbox_view_keywords_to_str(struct mailbox_view *view,
					 const uint8_t *bitmask);
const char *mailbox_view_get_random_flags(struct mailbox_view *view,
					  unsigned int client_idx);

struct message_metadata_static *
message_metadata_static_lookup_seq(struct mailbox_view *view, uint32_t seq);
struct message_metadata_static *
message_metadata_static_get(struct mailbox_storage *storage, uint32_t uid);
void message_metadata_static_assign_owner(struct mailbox_storage *storage,
					  struct message_metadata_static *ms);
void message_metadata_static_unref(struct mailbox_storage *storage,
				   struct message_metadata_static **ms);
void mailbox_view_expunge(struct mailbox_view *view, unsigned int seq);

bool mailbox_global_get_sent_date(struct mailbox_source *source,
				  struct message_global *msg,
				  time_t *date_r, int *tz_r);
bool mailbox_global_get_subject_utf8(struct mailbox_source *source,
				     struct message_global *msg,
				     const char **subject_r);

void mailboxes_init(void);
void mailboxes_deinit(void);

#endif
