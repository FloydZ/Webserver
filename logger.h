

#ifndef PG_LOGGER_H
#define PG_LOGGER_H

#define TPL_IDENT PACKAGE_NAME

void tp_log_init(const char *path, int mask);
void tp_log_write(int priority, const char *message, ...);
void tp_log_close(void);

void (*tp_syslog)(int priority, const char *message, ...);
void (*tp_closelog)(void);


/* end of log.h */

#endif  /*  PG_HELPER_H  */
