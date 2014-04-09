#include <common.h>
#include <pthread.h>
#include <limits.h>

static pthread_t *tids = NULL;
static worker_data_t *workersData = NULL;
static size_t numOfWorkers = 0;

pthread_mutex_t mlock = PTHREAD_MUTEX_INITIALIZER;

static void balanceWorkersThresholds(const struct config_options * const __restrict__);
static void *worker(void *);

void createWorkers(const struct config_options * const __restrict__ co, struct cidr * __restrict__ cidr_ptr)
{
  pthread_attr_t attr;
  worker_data_t *pdata;
  size_t i;

  assert(co != NULL);
  assert(cidr_ptr != NULL);

  numOfWorkers = co->threads;

  if ((tids = (pthread_t *)malloc(sizeof(pthread_t) * numOfWorkers)) == NULL)
  {
    ERROR("Error: Cannot allocate memory for worker threads ids.");
    exit(EXIT_FAILURE);
  }

  if ((workersData = (worker_data_t *)malloc(sizeof(worker_data_t) * numOfWorkers)) == NULL)
  {
    ERROR("Error: Cannot allocate memory for worker threads data.");
    exit(EXIT_FAILURE);
  }

  balanceWorkersThresholds(co);

  pthread_attr_init(&attr);

  /* PTHREAD_STACK_MIN should be sufficient (16 kB stack size) */
  if (pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN))
  {
    ERROR("Error setting workers thread stack size attribute.");
    exit(EXIT_FAILURE);
  }

  ;
  for (pdata = workersData, i = 0; i < numOfWorkers; i++, pdata++)
  {
    pdata->pktbuffer = NULL;
    pdata->tpktsize = workersData[i].upktsize = 0;
    pdata->co = (struct config_options *)co;
    pdata->protocol = co->ip.protocol;
    pdata->cidr_ptr = cidr_ptr;

    if (pthread_create(&tids[i], &attr, worker, pdata))
    {
      char msg[48];
      
      sprintf(msg, "Error: Cannot create worker thread #%d.", (int)i+1);
      ERROR(msg);
      exit(EXIT_FAILURE);
    }
  }

  pthread_attr_destroy(&attr);
}

void waitForWorkers(void)
{
  size_t i;

  assert(tids != NULL);
  assert(workersData != NULL);

  for (i = 0; i < numOfWorkers; i++)
    pthread_join(tids[i], NULL);
  free(tids);
  free(workersData);

  numOfWorkers = 0;
}

static void balanceWorkersThresholds(const struct config_options * const __restrict__ co)
{
  size_t i;
  div_t d;

  assert(co != NULL);
  assert(workersData != NULL);

  d = div(co->threshold, numOfWorkers);
  for (i = 0; i < numOfWorkers; i++)
    workersData[i].threshold = d.quot;
  for (i = 0; d.rem--; i++)
    workersData[i].threshold++;  
}

static void *worker(void *data)
{
  struct config_options *co;
  modules_table_t *ptbl;
  struct cidr *cidr_ptr;
  worker_data_t *pdata;

  pdata = data;
  ptbl = mod_table;
  co = pdata->co;
  cidr_ptr = pdata->cidr_ptr;

  if (co->ip.protocol != IPPROTO_T50)
  {
    ptbl += co->ip.protoname;
    pdata->protocol = co->ip.protocol;
  }

  while (co->flood || pdata->threshold-- > 0)
  {
    /* Set the destination IP address to RANDOM IP address. */
    if (cidr_ptr->hostid)
      pdata->daddr = htonl(cidr_ptr->__1st_addr + 
        (__RND(0) % cidr_ptr->hostid));

    if (co->ip.protocol == IPPROTO_T50)
      pdata->protocol = ptbl->protocol_id;

    /* NOTE: worker_data_t have all we need! */
    ptbl->func(data);

    sendPacket(data);

    if (co->ip.protocol == IPPROTO_T50)
      if ((++ptbl)->func == NULL)
        ptbl = mod_table;
  }

  return NULL;
}
