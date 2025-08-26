#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

/**
 * remove \n from fgets input
 */
void remove_trailing_newline(char *str);

/**
 * convert string to lowercase (in-place)
 */
void str_to_lower(char *str);

/**
 * safely read a line from stdin
 * buffer: destination buffer
 * size: max size of buffer
 * returns: 1 if success, 0 if EOF/error
 */
int safe_read_line(char *buffer, size_t size);

/**
 * exactly what you think.
*/
void press_enter_to_continue(void);

#endif