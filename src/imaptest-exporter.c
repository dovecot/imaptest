/* Copyright (c) ImapTest authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "imaptest-exporter.h"

ARRAY_DEFINE_TYPE(driver_ptr, const struct imaptest_exporter_driver *);

static ARRAY_TYPE(driver_ptr) drivers;
static const struct imaptest_exporter_driver *active_driver;

int
imaptest_exporter_register_driver(const struct imaptest_exporter_driver *driver)
{
	const struct imaptest_exporter_driver * const *ptr;
	unsigned int i;

	i_assert(driver != NULL);
	i_assert(driver->name != NULL);
	i_assert(driver->init != NULL);
	i_assert(driver->deinit != NULL);
	i_assert(driver->is_initialized != NULL);

	/* Initialize the array on first use */
	i_array_init(&drivers, 4);

	/* Check for duplicate name */
	for (i = 0; i < array_count(&drivers); i++) {
		ptr = array_idx(&drivers, i);
		if (strcmp(ptr[0]->name, driver->name) == 0) {
			i_error("Exporter driver '%s' already registered", driver->name);
			return -1;
		}
	}

	array_append(&drivers, &driver, 1);
	return 0;
}

int
imaptest_exporter_init(const char *driver_options)
{
	const char *driver_name, *options;
	unsigned int i;

	if (driver_options == NULL)
		return 0;

	/* Split on first ':' */
	const char *colon = strchr(driver_options, ':');
	if (colon != NULL) {
		driver_name = t_strdup_until(driver_options, colon);
		options = colon + 1;
	} else {
		driver_name = driver_options;
		options = "";
	}

	/* Look up the driver */
	for (i = 0; i < array_count(&drivers); i++) {
		const struct imaptest_exporter_driver * const *ptr;
		ptr = array_idx(&drivers, i);
		if (strcmp(ptr[0]->name, driver_name) == 0) {
			active_driver = ptr[0];
			break;
		}
	}

	if (active_driver == NULL) {
		string_t *str = t_str_new(128);
		str_printfa(str, "Unknown exporter driver '%s' (available: ", driver_name);
		for (i = 0; i < array_count(&drivers); i++) {
			const struct imaptest_exporter_driver * const *ptr;
			ptr = array_idx(&drivers, i);
			if (i > 0)
				str_append(str, ", ");
			str_append(str, ptr[0]->name);
		}
		str_append(str, ")");
		i_error("%s", str_c(str));
		return -1;
	}

	if (active_driver->init(options) < 0) {
		i_error("Failed to initialize exporter driver '%s'", driver_name);
		active_driver = NULL;
		return -1;
	}

	return 0;
}

void
imaptest_exporter_deinit(void)
{
	if (active_driver != NULL) {
		active_driver->deinit();
		active_driver = NULL;
	}
}

bool
imaptest_exporter_is_initialized(void)
{
	return active_driver != NULL && active_driver->is_initialized();
}
