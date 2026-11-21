/* Copyright (c) ImapTest authors, see the included COPYING file */

#ifndef IMAPTEST_EXPORTER_H
#define IMAPTEST_EXPORTER_H

/**
 * Exporter driver interface.
 *
 * Each driver implements these callbacks and registers itself at startup.
 * The framework dispatches init/deinit/is_initialized to the matched driver.
 */
struct imaptest_exporter_driver {
	/** Driver name (e.g. "jsonl"). Must be unique. */
	const char *name;

	/**
	 * Initialize the driver with its options string.
	 * Options are the part after "driver:" in the CLI argument.
	 * Returns 0 on success, -1 on failure (error logged).
	 */
	int (*init)(const char *options);

	/** Deinitialize — flush, close, clean up. */
	void (*deinit)(void);

	/** Check if the driver has been successfully initialized. */
	bool (*is_initialized)(void);
};

/**
 * Register a driver with the exporter framework.
 *
 * Must be called before imaptest_exporter_init().
 * Returns 0 on success, -1 if a driver with the same name is already registered.
 */
int imaptest_exporter_register_driver(const struct imaptest_exporter_driver *driver);

/**
 * Initialize the exporter framework.
 *
 * Parses the full "driver:options" string, looks up the driver by name,
 * and calls driver->init(options). Returns 0 on success, -1 on failure.
 * If no colon is found, the entire string is treated as the driver name
 * with an empty options string.
 */
int imaptest_exporter_init(const char *driver_options);

/**
 * Deinitialize the exporter framework.
 * Calls the active driver's deinit() callback, if any.
 */
void imaptest_exporter_deinit(void);

/**
 * Check if any exporter driver is initialized.
 */
bool imaptest_exporter_is_initialized(void);

#endif /* IMAPTEST_EXPORTER_H */
