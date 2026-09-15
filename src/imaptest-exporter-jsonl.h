/* Copyright (c) ImapTest authors, see the included COPYING file */

#ifndef IMAPTEST_EXPORTER_JSONL_H
#define IMAPTEST_EXPORTER_JSONL_H

/**
 * Register the JSONL exporter driver with the exporter framework.
 *
 * Must be called before imaptest_exporter_init().
 */
void imaptest_exporter_jsonl_register(void);

#endif /* IMAPTEST_EXPORTER_JSONL_H */
