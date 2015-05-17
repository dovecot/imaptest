#ifndef TEST_EXEC_H
#define TEST_EXEC_H

#include "test-parser.h"

struct tests_execute_context *tests_execute(const ARRAY_TYPE(test) *tests);
bool tests_execute_done(struct tests_execute_context **ctx);

void test_execute_cancel_by_client(struct imap_client *client);

#endif
