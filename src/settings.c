/* Copyright (c) ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "home-expand.h"
#include "settings.h"

void set_conf_default(struct settings *c)
{
	c->password = PASSWORD;
	c->username_template = USERNAME_TEMPLATE;
	c->host = HOST;
	c->port = PORT;
	c->mbox_path = home_expand(MBOX_PATH);
	c->clients_count = CLIENTS_COUNT;
	c->message_count_threshold = MESSAGE_COUNT_THRESHOLD;
	c->users_rand_start = 1;
	c->users_rand_count = USER_RAND;
	c->domains_rand_start = 1;
	c->domains_rand_count = DOMAIN_RAND;
	c->mech = "LOGIN";
}
