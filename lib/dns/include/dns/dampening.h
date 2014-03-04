/*
 * (C) 2012 Lutz Donnerhacke
 */

#ifndef DNS_DAMPENING_H
#define DNS_DAMPENING_H 1

#include <isc/mutex.h>
#include <isc/stdtime.h>
#include <dns/acl.h>

typedef enum {
   DNS_DAMPENING_STATE_NORMAL,
   DNS_DAMPENING_STATE_SUPPRESS
} dns_dampening_state_t;

typedef struct dns_dampening_entry {
   isc_netaddr_t netaddr;
   isc_stdtime_t last_updated;
   dns_messageid_t last_id;
   unsigned int dampening : 1, last_id_count : 15, penalty : 16;
} dns_dampening_entry_t;

typedef struct dns_dampening_implementation {
   /* Interals */
   void * data;
   struct dns_dampening * conf;
   /* API */
   void (*destroy)(void **);
   dns_dampening_entry_t * (*search)(void *, const isc_netaddr_t * netaddr);
   void (*add)(void *, const isc_netaddr_t * netaddr, uint16_t points, isc_stdtime_t now);
   void (*update)(void *, dns_dampening_entry_t ** entry, uint16_t points, isc_stdtime_t now);
   /* Used by externals */
   isc_mutex_t lock;
   struct {
      struct timeval lock, search, update, add;
      unsigned int allowed, denied, skipped;
      isc_stdtime_t last_report;
   } statistics;
}  dns_dampening_implementation_t;

typedef struct dns_dampening {
   dns_acl_t	*exempt;
   int		max_entries;
   dns_dampening_implementation_t * workers;
   int workers_count;

   struct dns_dampening_prefix {
      unsigned int ipv4;
      unsigned int ipv6;
   } prefixlen;
   
   struct dns_dampening_decay {
      int halflife;
      int updatedelay;
   } decay;
    
   struct dns_dampening_limit {
      unsigned int
	maximum            : 16,
	enable_dampening   : 16,
	disable_dampening  : 16,
	irrelevant         : 16;
   } limit;
   
   struct dns_dampening_score {
      unsigned int
	first_query  : 16,
	per_query    : 16,
	duplicates   : 16,
	qtype_any    : 16,
	size_penalty : 16,
	minimum_size : 16,
	maximum_size : 16;
   } score;
   
   struct dns_dampening_statistics {
      int report_interval;
   } statistics;
   
} dns_dampening_t;

dns_dampening_state_t dns_dampening_query(dns_dampening_t *, const isc_sockaddr_t *, isc_stdtime_t, int *);
void dns_dampening_score_qtype(dns_dampening_t *, const isc_sockaddr_t *, isc_stdtime_t, dns_messageid_t, int);
void dns_dampening_score_size(dns_dampening_t *, const isc_sockaddr_t *, isc_stdtime_t, int);
isc_result_t dns_dampening_init(dns_view_t *, int);
void dns_dampening_destroy(dns_view_t *);

#endif
