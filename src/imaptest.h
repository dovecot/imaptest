#ifndef IMAPTEST_H
#define IMAPTEST_H

#define STATE_IS_VISIBLE_AT(i) (states[(i)].probability != 0)

/**
 * Validate and expand an output file path.
 *
 * Expands ~ prefix via home_expand(), ensures parent directories exist
 * via mkdir_parents()/stat_first_parent(), and returns the expanded path.
 *
 * Returns 0 on success, -1 on failure (with error logged).
 * Safe for both relative and absolute paths — absolute paths are
 * accepted as-is (caller controls which paths are allowed).
 */
int validate_output_path(const char *path, char **expanded_r);

#endif
