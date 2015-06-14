#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "logger.h"

static FILE *log_file;
static int log_maskpri;


static void log_close(void)
{
    if (log_file != NULL) {
        fclose(log_file);
        log_file = NULL;
    }
}

static size_t logdate(char *msg, size_t len)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    return tm ? strftime(msg, len, "%a, %d %b %Y %T %z", tm) : 0;
}

static void log_write(int priority, const char *message, ...)
{
    if ((priority) & log_maskpri) {
        char date[60];
        size_t len = logdate(date, sizeof date);
        fwrite(date, len, 1, log_file);
        /**< fwrite(date, len, 1, "\n"); */
        /**< fwrite(get_prio(priority), 10, 1, log_file); */

        va_list va;
        va_start(va, message);
        vfprintf(log_file, message, va);
        vfprintf(log_file, "\n", va);
        va_end(va);
    }
}

void tp_log_init(const char *path, int mask)
{
    if (path) {
        if ((log_file = fopen(path, "a")) != NULL) {
            tp_syslog = log_write;
            tp_closelog = log_close;
            log_maskpri = mask;
            return;
        }
        perror(path);
    }
}
