/* ncdu - NCurses Disk Usage

  Copyright (c) Yorhel
  Shell support: Copyright (c) 2014 Thomas Jarosch

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/

#include "config.h"
#include "global.h"
#include "dirlist.h"
#include "util.h"

#include <ncurses.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

static void set_level(void) {
  static int done = 0;
  const char *lvl;
  char nlvl[2];
  if(done)
    return;
  lvl = getenv("NCDU_LEVEL");
  /* too lazy to count beyond 9 */
  if(lvl && *lvl >= '1' && *lvl < '9' && lvl[1] == 0) {
    nlvl[0] = 1 + *lvl;
    nlvl[1] = 0;
    setenv("NCDU_LEVEL", nlvl, 1);
  } else
    setenv("NCDU_LEVEL", "1", 1);
  done++;
}

void shell_draw(void) {
  const char *full_path;
  int res;

  /* suspend ncurses mode */
  def_prog_mode();
  endwin();

  full_path = getpath(dirlist_par);
  res = chdir(full_path);
  if (res != 0) {
    reset_prog_mode();
    clear();
    printw("ERROR: Can't change directory: %s (errcode: %d)\n"
           "\n"
           "Press any key to continue.",
           full_path, res);
  } else {
    const char *shell = getenv("NCDU_SHELL");
    if (shell == NULL) {
      shell = getenv("SHELL");
      if (shell == NULL)
        shell = DEFAULT_SHELL;
    }

    set_level();
    res = system(shell);

    /* resume ncurses mode */
    reset_prog_mode();

    if (res == -1 || !WIFEXITED(res) || WEXITSTATUS(res) == 127) {
      clear();
      printw("ERROR: Can't execute shell interpreter: %s\n"
             "\n"
             "Press any key to continue.",
             shell);
    }
  }

  refresh();
  pstate = ST_BROWSE;
}

void shell_init(void) {
  pstate = ST_SHELL;
}
