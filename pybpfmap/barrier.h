#ifndef __PYBPFMAP_BARRIERS

#define __PYBPFMAP_BARRIERS 1

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

#define READ_ONCE(x)  ({ typeof(x) ___x = ACCESS_ONCE(x); ___x; })

#define WRITE_ONCE(x, val) do { ACCESS_ONCE(x) = (val); } while (0)

static inline unsigned long int smp_load_acquire_long_int(void *p,
                                                          unsigned long int offset)
{
	char *loc = (char *)p;
	loc += offset;
	unsigned long int res = READ_ONCE(*((unsigned long int *)loc));
	__sync_synchronize();
	return res;
};

static inline void smp_store_release_long_int(void *p,
                                              unsigned long int offset,
                                              unsigned long int value)
{                                                                                                                                       
	char *loc = (char *)p;
	loc += offset;
	WRITE_ONCE(*((unsigned long int *)loc), value);
	__sync_synchronize();
};

static inline unsigned long int smp_load_acquire_int(void *p,
                                                     unsigned long int offset)
{
	char *loc = (char *)p;
	loc += offset;
	unsigned int res = READ_ONCE(*((unsigned int *)loc));
	__sync_synchronize();
	return res;
};

static inline void smp_store_release_int(void *p,
                                              unsigned long int offset,
                                              unsigned int value)
{                                                                                                                                       
	char *loc = (char *)p;
	loc += offset;
	WRITE_ONCE(*((unsigned int *)loc), value);
	__sync_synchronize();
};


#endif
