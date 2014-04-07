#ifndef __WORKER_INCLUDED__
#define __WORKER_INCLUDED__

void createWorkers(const struct config_options * const __restrict__, struct cidr * __restrict__);
void waitForWorkers(void);

#endif

