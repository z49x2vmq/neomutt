/**
 * @file
 * Convenience wrapper for the debug headers
 *
 * @authors
 * Copyright (C) 2019 Richard Russon <rich@flatcap.org>
 *
 * @copyright
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @page lib_debug DEBUG: Debugging tools
 *
 * Debugging tools
 *
 * | File                | Description                |
 * | :------------------ | :------------------------- |
 * | debug/backtrace.c   | @subpage debug_backtrace   |
 * | debug/common.c      | @subpage debug_common      |
 * | debug/graphviz.c    | @subpage debug_graphviz    |
 * | debug/notify.c      | @subpage debug_notify      |
 * | debug/parse_test.c  | @subpage debug_parse       |
 * | debug/window.c      | @subpage debug_window      |
 */

#ifndef MUTT_DEBUG_LIB_H
#define MUTT_DEBUG_LIB_H

#include "email/lib.h"

struct MuttWindow;
struct NotifyCallback;

// Backtrace
void show_backtrace(void);

// Common
const char *win_name(const struct MuttWindow *win);

// Graphviz
void        add_flag               (struct Buffer *buf, bool is_set, const char *name);
void        dump_graphviz          (const char *title);
void        dump_graphviz_email    (struct Email *e, int num);
const char *get_content_disposition(enum ContentDisposition disp);
const char *get_content_encoding   (enum ContentEncoding enc);
const char *get_content_type       (enum ContentType type);

// Notify
int debug_notify_observer(struct NotifyCallback *nc);

// Parse Set
void test_parse_set(void);

// Window
void debug_win_dump(void);

#endif /* MUTT_DEBUG_LIB_H */
