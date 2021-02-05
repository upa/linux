#ifndef _LKL_HIJACK_INIT_H
#define _LKL_HIJACK_INIT_H

extern int lkl_running;
extern int dual_fds[];

#define EVENTFDS_NUM	64
extern int event_fds[];
int get_host_eventfd();

#endif /*_LKL_HIJACK_INIT_H */
