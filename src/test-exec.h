#ifndef TEST_EXEC_H
#define TEST_EXEC_H

#include "test-parser.h"

void tests_execute(const ARRAY_TYPE(test) *tests);
void test_execute_cancel_by_client(struct client *client);

#endif
