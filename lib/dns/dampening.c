/*
 * (C) 2012 Lutz Donnerhacke
 */

#include <config.h>
#include <math.h>
#include <sys/time.h>

/*
#include <isc/buffer.h>
#include <isc/net.h>
#include <isc/netaddr.h>
#include <isc/print.h>
#include <isc/stdlib.h>
#include <isc/string.h>
#include <isc/util.h>
#include <dns/db.h>
#include <dns/fixedname.h>
#include <dns/rdata.h>
#include <dns/rdataset.h>
#include <dns/rdatastruct.h>
#include <dns/result.h>
#include <dns/rpz.h>
#include <dns/view.h>
 */

#include <isc/mem.h>
#include <dns/dampening.h>
#include <dns/log.h>
#include <dns/view.h>

#define DAMPENING_STATISTICS_DO(impl, field, command)	do { \
   struct timeval before, after, diff; \
   gettimeofday(&before, NULL); \
   command; \
   gettimeofday(&after, NULL); \
   timersub(&after, &before, &diff); \
   timeradd(&diff, &((impl)->statistics.field), &after); \
   (impl)->statistics.field = after; \
}  while(0)
#define DAMPENING_STATISTICS_INC(impl, field)	do { (impl)->statistics.field++; } while(0)


static isc_result_t heap_init (isc_mem_t *, dns_dampening_implementation_t *, dns_dampening_t *, uint16_t);
static isc_result_t queue_init(isc_mem_t *, dns_dampening_implementation_t *, dns_dampening_t *, uint16_t);

static isc_result_t
(*(implementations[])) (isc_mem_t *, dns_dampening_implementation_t *,
			dns_dampening_t *, uint16_t) = {
	heap_init , queue_init
};
   


static void
extract_prefix(isc_netaddr_t * prefix, const isc_netaddr_t * addr, const struct dns_dampening_prefix * prefixlen) {
   int bytes, bits, len, max = -1;
   unsigned char *p = NULL;
   
   INSIST(prefix != NULL);
   INSIST(addr != NULL);
   INSIST(prefixlen != NULL);
   
   memcpy(prefix, addr, sizeof(*prefix));
   
   switch(addr->family) {
    case AF_INET:
      p = (unsigned char *)&(prefix->type.in);
      max = 32;
      len = prefixlen->ipv4;
      break;
    case AF_INET6:
      p = (unsigned char *)&(prefix->type.in6);
      max = 128;
      len = prefixlen->ipv6;
      break;
    default:
      return;
   }

   INSIST(0 <= len && len <= max);
   INSIST(p != NULL);
   
   bytes = len / 8;
   bits  = len % 8;
   
   if(bits > 0)
     p[bytes++] &= (0xFF << (8-bits)) & 0xFF;

   for(max /= 8; bytes < max; bytes++)
     p[bytes] = 0;

}

static void
log_dampening(const dns_dampening_t * conf, const isc_netaddr_t * prefix, int enabled) {
   char pb[ISC_NETADDR_FORMATSIZE];
   int len;
   
   INSIST(conf != NULL);
   INSIST(prefix != NULL);
   
   switch(prefix->family) {
    case AF_INET : len = conf->prefixlen.ipv4; break;
    case AF_INET6: len = conf->prefixlen.ipv6; break;
    default      : return;
   }

   if(isc_log_wouldlog(dns_lctx, ISC_LOG_INFO)) {
      isc_netaddr_format(prefix, pb, sizeof(pb));
      isc_log_write(dns_lctx, DNS_LOGCATEGORY_DAMPENING,
		    DNS_LOGMODULE_REQUEST, ISC_LOG_INFO,
		    "%s/%d dampening %s.",pb, len,
		    enabled ? "activated" : "removed");
   }
}

/*
 * Decay the penalty value, if necessary and add the new points.
 * Return zero if the entry is below the drop limit. Caller should remove it
 * from the table. Otherwise the caller has to update the structure to reflect
 * the modified values.
 */
static int
update_penalty(const dns_dampening_t * conf, dns_dampening_entry_t * entry,
	       uint16_t points, isc_stdtime_t now) {
   int timediff;
   
   INSIST(conf != NULL);
   INSIST(entry != NULL);
   
   timediff = now - entry->last_updated;
   if(timediff > conf->decay.updatedelay) {
      float penalty = entry->penalty;
      penalty *= exp(-(0.693*timediff)/conf->decay.halflife);
      entry->penalty = penalty;
      entry->last_updated = now;
   }
   if(entry->penalty >= conf->limit.maximum - points)
     entry->penalty = conf->limit.maximum;
   else
     entry->penalty += points;

   if(entry->dampening == 1 && entry->penalty < conf->limit.disable_dampening) {
      entry->dampening = 0;
      log_dampening(conf, &entry->netaddr, entry->dampening);
   }
   
   if(entry->dampening == 0 && entry->penalty > conf->limit.enable_dampening) {
      entry->dampening = 1;
      log_dampening(conf, &entry->netaddr, entry->dampening);
   }
   
   if(entry->penalty < conf->limit.irrelevant &&
      timediff > conf->decay.updatedelay) {
      return 0;
   } else {
      return 1;
   }
}

dns_dampening_state_t
dns_dampening_query(dns_dampening_t * damp, const isc_sockaddr_t * addr,
		    isc_stdtime_t now, int * penalty) {
   isc_netaddr_t netaddr, prefix;
   dns_dampening_state_t final_state = DNS_DAMPENING_STATE_NORMAL, state = DNS_DAMPENING_STATE_NORMAL;
   dns_dampening_entry_t * entry;
   dns_dampening_implementation_t *impl;
   int max_penalty = -2;

   RUNTIME_CHECK( damp != NULL );
   RUNTIME_CHECK( addr != NULL );

   isc_netaddr_fromsockaddr(&netaddr, addr);
   extract_prefix(&prefix, &netaddr, &(damp->prefixlen));
   
   for(impl = damp->workers;
       impl - damp->workers < damp->workers_count;
       impl++) {
      
      if(damp->exempt != NULL) {
	 int match;
	 
	 if (ISC_R_SUCCESS == dns_acl_match(&netaddr, NULL, damp->exempt,
					    NULL, &match, NULL) &&
	     match > 0) {
	    max_penalty = ISC_MAX(max_penalty, -1);
	    DAMPENING_STATISTICS_INC(impl,skipped);
	    continue;
	 }
      }
      
      DAMPENING_STATISTICS_DO(impl, lock, LOCK(&impl->lock));
      
      if(damp->statistics.report_interval > 0 &&
	 damp->statistics.report_interval + impl->statistics.last_report <= now) {
	 if(isc_log_wouldlog(dns_lctx, ISC_LOG_INFO))
	   isc_log_write(dns_lctx, DNS_LOGCATEGORY_DAMPENING,
			 DNS_LOGMODULE_REQUEST, ISC_LOG_INFO,
			 "Stats for #%d: queries %u/%u/%u: lock=%ld.%06ld, search=%ld.%06ld, update=%ld.%06ld, add=%ld.%06ld",
			 impl - damp->workers,
			 impl->statistics.allowed, impl->statistics.denied, impl->statistics.skipped,
			 impl->statistics.lock.tv_sec, impl->statistics.lock.tv_usec,
			 impl->statistics.search.tv_sec, impl->statistics.search.tv_usec,
			 impl->statistics.update.tv_sec, impl->statistics.update.tv_usec,
			 impl->statistics.add.tv_sec, impl->statistics.add.tv_usec);
	 memset(&impl->statistics, 0, sizeof(impl->statistics));
	 impl->statistics.last_report = now;
      }
      
      DAMPENING_STATISTICS_DO(impl, search, entry = impl->search(impl->data, &prefix));
      if(entry == NULL) {
	 state = DNS_DAMPENING_STATE_NORMAL;
	 DAMPENING_STATISTICS_DO(impl, add, impl->add(impl->data, &prefix, damp->score.first_query, now));
	 max_penalty = ISC_MAX(max_penalty, 0);
      } else {
	 state = entry->dampening == 1
	   ? DNS_DAMPENING_STATE_SUPPRESS
	   : DNS_DAMPENING_STATE_NORMAL;
	 max_penalty = ISC_MAX(max_penalty, entry->penalty);
	 DAMPENING_STATISTICS_DO(impl, update, impl->update(impl->data, &entry, damp->score.per_query, now));
      }
      
      if(state == DNS_DAMPENING_STATE_NORMAL) {
	 DAMPENING_STATISTICS_INC(impl, allowed);
      } else {
	 DAMPENING_STATISTICS_INC(impl, denied);
	 final_state = state;	       /* any dampening suffice */
      }

      UNLOCK(&impl->lock);
   }
   
   if(penalty != NULL) *penalty = max_penalty;
   return final_state;
}

void dns_dampening_score_qtype(dns_dampening_t * damp,
			       const isc_sockaddr_t * addr,
			       isc_stdtime_t now,
			       dns_messageid_t message_id,
			       int qtype) {
   isc_netaddr_t netaddr, prefix;
   dns_dampening_entry_t * entry;
   uint16_t points;
   dns_dampening_implementation_t *impl;
   
   RUNTIME_CHECK( damp != NULL );
   RUNTIME_CHECK( addr != NULL );
   
   isc_netaddr_fromsockaddr(&netaddr, addr);
   extract_prefix(&prefix, &netaddr, &(damp->prefixlen));
  
   for(impl = damp->workers;
       impl - damp->workers < damp->workers_count;
       impl++) {

      if(damp->exempt != NULL) {
	 int match;
	 
	 if (ISC_R_SUCCESS == dns_acl_match(&netaddr, NULL, damp->exempt,
					    NULL, &match, NULL) &&
	     match > 0) {
	    DAMPENING_STATISTICS_INC(impl,skipped);
	    continue;
	 }
      }
      
      DAMPENING_STATISTICS_DO(impl, lock, LOCK(&impl->lock));
      DAMPENING_STATISTICS_DO(impl, search, entry = impl->search(impl->data, &prefix));
      
      if(entry != NULL) {
	 switch(qtype) {
	  case dns_rdatatype_any: points = damp->score.qtype_any; break;
	  default               : points = 0;                     break;
	 }
	 
	 if(entry->last_id == message_id) {
	    points += (entry->last_id_count++)*damp->score.duplicates;
	 } else {
	    entry->last_id = message_id;
	    entry->last_id_count = 1;
	 }

	 DAMPENING_STATISTICS_DO(impl, update, impl->update(impl->data, &entry, points, now));
      }

      UNLOCK(&impl->lock);
   }
}

void dns_dampening_score_size(dns_dampening_t * damp, const isc_sockaddr_t * addr, isc_stdtime_t now, int length) {
   isc_netaddr_t netaddr, prefix;
   dns_dampening_entry_t * entry;
   uint16_t points;
   dns_dampening_implementation_t *impl;
   
   RUNTIME_CHECK( damp != NULL );
   RUNTIME_CHECK( addr != NULL );

   isc_netaddr_fromsockaddr(&netaddr, addr);
   extract_prefix(&prefix, &netaddr, &(damp->prefixlen));
   
   for(impl = damp->workers;
       impl - damp->workers < damp->workers_count;
       impl++) {
   
      if(damp->exempt != NULL) {
	 int match;
	 
	 if (ISC_R_SUCCESS == dns_acl_match(&netaddr, NULL, damp->exempt,
					    NULL, &match, NULL) &&
	     match > 0) {
	    DAMPENING_STATISTICS_INC(impl,skipped);
	    continue;
	 }
      }
   
      DAMPENING_STATISTICS_DO(impl, lock, LOCK(&impl->lock));
      DAMPENING_STATISTICS_DO(impl, search, entry = impl->search(impl->data, &prefix));
      if(entry != NULL) {
	 length = ISC_MAX(length, damp->score.minimum_size);
	 length = ISC_MIN(length, damp->score.maximum_size);
	 points = damp->score.size_penalty
	   * (length - damp->score.minimum_size)
	   / (damp->score.maximum_size - damp->score.minimum_size);
	 DAMPENING_STATISTICS_DO(impl, update, impl->update(impl->data, &entry, points, now));
      }

      UNLOCK(&impl->lock);
   }
}

isc_result_t dns_dampening_init(dns_view_t * view, int initial_size) {
   isc_result_t result;
   int i, num_workers = sizeof(implementations)/sizeof(*implementations);
   
   INSIST( view != NULL );
   INSIST( view->dampening == NULL );
   RUNTIME_CHECK( 0 < initial_size && initial_size <= ISC_UINT16_MAX );

   view->dampening = isc_mem_get(view->mctx, sizeof(*(view->dampening)));
   if( view->dampening == NULL ) {
      result = ISC_R_NOMEMORY;
      goto cleanup;
   }
   memset( view->dampening, 0, sizeof(*(view->dampening)) );

   view->dampening->workers = isc_mem_get(view->mctx, num_workers * sizeof(*(view->dampening->workers)));
   if( view->dampening->workers == NULL ) {
      result = ISC_R_NOMEMORY;
      goto cleanup;
   }
   memset( view->dampening->workers, 0, num_workers * sizeof(*(view->dampening->workers)) );
   
   for(i = 0; i < num_workers; i++) {
      result = implementations[i](view->mctx,
				  view->dampening->workers + i,
				  view->dampening, initial_size);
      if( ISC_R_SUCCESS != result) {
	 dns_dampening_destroy( view );
	 goto cleanup;
      }
   
      result = isc_mutex_init(&view->dampening->workers[i].lock);
      if( result != ISC_R_SUCCESS ) {
	 dns_dampening_destroy( view );
	 goto cleanup;
      }
   }
   view->dampening->workers_count = num_workers;
   INSIST( view->dampening != NULL );

   result = ISC_R_SUCCESS;

cleanup:
   return result;
}

void dns_dampening_destroy(dns_view_t * view) {
   int i, num_workers = sizeof(implementations)/sizeof(*implementations);

   INSIST( view != NULL );
   INSIST( view->dampening != NULL );
   
   if(view->dampening->exempt != NULL)
     dns_acl_detach(&view->dampening->exempt);

   for( i = view->dampening->workers_count; i-- > 0; ) {
      DESTROYLOCK(&view->dampening->workers[i].lock);
      view->dampening->workers[i].destroy(&(view->dampening->workers[i].data));
   }
   view->dampening->workers_count = 0;
   
   isc_mem_put(view->mctx, view->dampening->workers, num_workers * sizeof(*(view->dampening->workers)));
   view->dampening->workers = NULL;
   
   isc_mem_put(view->mctx, view->dampening, sizeof(*(view->dampening)));
   view->dampening = NULL;
	       
   INSIST( view->dampening == NULL );
}


/********************************************************
 * Heap
 ********************************************************/

/*
 * Heap-Implementation
 * ~~~~~~~~~~~~~~~~~~~
 * 
 * The assumed access pattern is that high penalty clients will be cause
 * most of the queries. The used data structure is therefore a heap.
 * 
 * The following operations are implemented:
 * 
 *  a) Searching an IP by travering the heap array from front (high values)
 *     to the end (beware of a partially filled heap).
 * 
 *  b) Adding a new IP (if not found) by overwriting the very last entry
 *     of the heap, if the heap is full. This will cause one of the low
 *     penality entries to be lost.
 * 
 *  c) If a searched IP was found, the last updated timestamp is used to
 *     recalculate the penality value (expotential decrease plus new
 *     points), update the state, and rebalanced the heap for this modified
 *     entry only. If the penality value falls below a certain limit, the
 *     entry is removed from the heap.
 * 
 *  d) The top, last, and a random node are recalculated and rebalanced
 *     after each update or insertion, if the nodes were not updated
 *     recently.
 * 
 * Using this approach, the operations on the heap will be O(log n) on
 * each access. There is no need for a regular maintainence activity.
 * 
 * See: http://lutz.donnerhacke.de/eng/Blog/DNS-Dampening
 * 
 */

typedef struct {
   dns_dampening_entry_t * heap;
   uint16_t last, length;
   isc_mem_t * mctx;
   dns_dampening_t * conf;
} heap_t;


static int
heap_below_top(heap_t * d, uint16_t entry) {
   RUNTIME_CHECK(entry > 0 && entry <= d->last);
   return entry <= 1 ||
     (d->heap[entry].penalty <= d->heap[entry/2].penalty);
}

static void
heap_swap(heap_t * d, uint16_t a, uint16_t b) {
   RUNTIME_CHECK(a > 0 && a <= d->last);
   RUNTIME_CHECK(b > 0 && b <= d->last);
   RUNTIME_CHECK(a != b);
   
   memcpy(d->heap + 0, d->heap + a, sizeof(*(d->heap)));
   memcpy(d->heap + a, d->heap + b, sizeof(*(d->heap)));
   memcpy(d->heap + b, d->heap + 0, sizeof(*(d->heap)));
}

static void
heap_up(heap_t * d, uint16_t entry) {
   uint16_t e;
   
   RUNTIME_CHECK(entry > 0 && entry <= d->last);
   
   for(e = entry/2; e > 0; entry = e, e = entry/2) {
      if(d->heap[entry].penalty <= d->heap[e].penalty)
	break;
      heap_swap(d, entry, e);
   }
}

static void
heap_down(heap_t * d, uint16_t entry) {
   uint16_t e;
   
   RUNTIME_CHECK(entry > 0 && entry <= d->last);
   
   for(e = 2*entry; e <= d->last; entry = e, e = 2*entry) {
      if(e+1 <= d->last &&
	 d->heap[e].penalty <= d->heap[e+1].penalty)
	e = e+1;

      if(d->heap[e].penalty <= d->heap[entry].penalty)
	break;

      heap_swap(d, entry, e);
   }
}



/*
 * Simple search though the heap, exploiting the feature, that the heap
 * is mapped to a continiously filled, linear array. High penalty values
 * occur first, so they are searched first.
 * Returns DAMPENING_NOTHING if no match.
 */
static dns_dampening_entry_t * heap_search(void * data, const isc_netaddr_t * netaddr) {
   heap_t * d = data;
   uint16_t i;
   
   INSIST(d != NULL);
   REQUIRE(netaddr != NULL);

   for(i = 1; i <= d->last; i++) {
      if(ISC_TRUE == isc_netaddr_equal(&d->heap[i].netaddr, netaddr))
	return &d->heap[i];
   }
   return NULL;
}

/*
 * Update an existing entry with new points
 */
static void
heap_update1(void * data, dns_dampening_entry_t ** pentry, uint16_t points, isc_stdtime_t now) {
   heap_t * d = data;
   uint16_t e;
   
   INSIST(d != NULL);
   REQUIRE(pentry != NULL && *pentry != NULL);
   e = *pentry - d->heap;
   RUNTIME_CHECK(0 < e && e <= d->last);
   
   if(update_penalty(d->conf, *pentry, points, now) == 0) {
      /* Shrink heap */
      if(e < d->last) {
	 heap_swap(d, e, d->last);
      } else {
	 e = 0;
      }
      d->last--;
   }
   *pentry = NULL;		       /* prevent further use */
   
   if(e > 0) {
      if(heap_below_top(d, e))
	heap_down(d, e);
      else
	heap_up(d, e);
   }
}

/*
 * Expire penalties
 */
static void
heap_expire(void * data, isc_stdtime_t now) {
   heap_t * d = data;
   uint16_t poi[3] = { 1, d->last, 1+(random()%(d->last)) };
   unsigned int i;
   
   for(i=0; i<sizeof(poi)/sizeof(*poi); i++) {
      dns_dampening_entry_t * entry = d->heap + poi[i];
      
      if(0 < poi[i] && poi[i] <= d->last &&
	 now > entry->last_updated + d->conf->decay.updatedelay)
	heap_update1(data, &entry, 0, now);
   }
}

/*
 * Update an existing entry and expire
 */
static void
heap_update(void * data, dns_dampening_entry_t ** pentry, uint16_t points, isc_stdtime_t now) {
   heap_update1(data, pentry, points, now);
   heap_expire(data, now);
}


/*
 * Add an element to the end (eventually overwrite the last one)
 */
static void
heap_add(void * data, const isc_netaddr_t * netaddr, uint16_t points, isc_stdtime_t now) {
   heap_t * d = data;
   dns_dampening_entry_t * entry;

   INSIST(d != NULL);
   REQUIRE(netaddr != NULL);

   entry = d->heap + d->last;
   if(d->last < d->length - 1) {
      d->last++;
      entry++;
   } else {
      update_penalty(d->conf, entry, 0, now);
      if(entry->penalty > points) {
	 if(entry->penalty > d->conf->limit.irrelevant) {
	    if(isc_log_wouldlog(dns_lctx, ISC_LOG_WARNING))
	      isc_log_write(dns_lctx, DNS_LOGCATEGORY_DAMPENING,
			    DNS_LOGMODULE_REQUEST, ISC_LOG_WARNING,
			    "Dampening heap table overflow! Restarting with empty table.");
	    d->last = 1;
	    entry = d->heap + d->last;
	 } else
	   return;		       /* don't add */
      }
   }

   memset(entry, 0, sizeof(*entry));
   memcpy(&entry->netaddr, netaddr, sizeof(entry->netaddr));
   entry->last_updated = now;

   heap_update(data, &entry, points, now);
}

static void
heap_destroy(void ** pdata) {
   INSIST(pdata != NULL);

   if(*pdata != NULL) {
      heap_t * d = *pdata;

      if(d->heap != NULL)
	isc_mem_put(d->mctx, d->heap, d->length * sizeof(*(d->heap)));
      
      isc_mem_put(d->mctx, d, sizeof(*d));
      *pdata = NULL;
   }
   
   INSIST(*pdata == NULL);
}


/*
 * Set up the heap: allocate the memory range. Change of size is possible,
 * if heap_last is untouched.
 */
isc_result_t heap_init(isc_mem_t * mctx, dns_dampening_implementation_t * impl, dns_dampening_t * conf, uint16_t size) {
   heap_t * d;

   INSIST(mctx != NULL);
   INSIST(impl != NULL);
   INSIST(size > 0);
   
   impl->destroy = heap_destroy;
   
   impl->data = d = isc_mem_get(mctx, sizeof(*d));
   if(d == NULL)
     return ISC_R_NOMEMORY;
   memset(d, 0, sizeof(*d));
   
   d->length = size + 1;
   d->heap = isc_mem_get(mctx, d->length * sizeof(*(d->heap)));
   d->last = 0;
   d->mctx = mctx;
   d->conf = conf;
   if(d->heap == NULL) {
      impl->destroy(&impl->data);
      return ISC_R_NOMEMORY;
   }
   
   impl->search  = heap_search;
   impl->add     = heap_add;
   impl->update  = heap_update;
   
   if(isc_log_wouldlog(dns_lctx, ISC_LOG_INFO))
     isc_log_write(dns_lctx, DNS_LOGCATEGORY_DAMPENING,
		   DNS_LOGMODULE_REQUEST, ISC_LOG_INFO,
		   "Heap initialized to %d entries: %u bytes.",
		   size, d->length * sizeof(*(d->heap)));
   
   return ISC_R_SUCCESS;
}

/********************************************************
 * Quere
 ********************************************************/

/*
 * Queue-Implementation
 * ~~~~~+~~~~~~~~~~~~~~
 * 
 * Any client operation should be performed in constant time, unless really
 * strange condtions occur. So the natural data structure is a hash.
 * 
 * The following operations are implemented:
 * 
 *  a) Searching an IP by hashing and travering a linked list in the case of
 *     duplicates. In order to catch attacker IPs quickly, the least recent
 *     entry is always moved to the front of the list.
 * 
 *     Measurements show, that a ordered list is strictly slower than the LRU
 *     approach. Even if unknown entries require a full search of the hash
 *     duplicates.
 * 
 *  b) If the searched IP was not found, a new entry is allocated and linked
 *     into the front of the associeated hash list. If the storage is full,
 *     the least used entry is recalculated using the last update timestamp
 *     and the highest penalty (old or new) is moved to the front of a
 *     decay queue. So the least used entry is always at the rear of the queue.
 * 
 *  c) If a searched IP was found, the penalty is recalculated and moved to
 *     the front of the decay queue. If the penality value falls below a
 *     certain limit, the entry is removed from the queue and the hash list.
 *     This operation requires a double linked list for the queue.
 * 
 * Using this approach, the operations on the data structure will be O(1) on
 * each access. There is no need for a regular maintainence activity.
 * 
 * The free space is maintained by reusing the single link fields of the hash
 * linked list. The very first entry is used as a sentiel node for all lists.
 * 
 * This algorithms was developed by my collegue Jens.
 * 
 */

typedef struct {
   dns_dampening_entry_t entry;
   uint16_t list_next, queue_next, queue_prev;
} queue_entry_t;

typedef struct {
   queue_entry_t * field;
   uint16_t * hash;
   uint16_t length;
   isc_mem_t * mctx;
   dns_dampening_t * conf;
} queue_t;

#define QUEUE_AVAIL(d)	((d)->field[0].list_next)
#define QUEUE_FRONT(d)	((d)->field[0].queue_next)
#define QUEUE_REAR(d)	((d)->field[0].queue_prev)

/*
 * Hashing using a variant of the Adler32 algorithm. I had touble
 * with generic hash functions, the full content of netaddr varies
 * between queries for the same IP.
 */
static uint16_t
queue_makehash(const queue_t * d, const isc_netaddr_t * netaddr) {
   uint16_t a = 0, b = 0;
   const unsigned char * buff = (const unsigned char*)&netaddr->type;
   unsigned int i;

   INSIST(d != NULL);
   RUNTIME_CHECK(netaddr != NULL);
   
   for(i= netaddr->family == AF_INET  ? sizeof(netaddr->type.in ) :
          netaddr->family == AF_INET6 ? sizeof(netaddr->type.in6) :
                                        sizeof(netaddr->type    ) ;
       i-->0; ) {
      a = a + buff[i];
      b = b + a;
   }
   
   return ((b << 8) + a) % d->length;
}

/*
 * Searching the entry by hashing the address and searching the link list
 * of duplicates. If found, move the entry to the front.
 */
static dns_dampening_entry_t *
queue_search(void * data, const isc_netaddr_t * netaddr) {
   queue_t * d = data;
   uint16_t h = queue_makehash(data, netaddr), i, j=0;

   INSIST(data != NULL);
   INSIST(h < d->length);
   
   for(i = d->hash[h]; i > 0; i = d->field[j=i].list_next) {
      INSIST(0 < i && i < d->length);
      
      if(ISC_TRUE == isc_netaddr_equal(netaddr, &d->field[i].entry.netaddr)) {
	 if(j>0) {
	    /* Move to front */
	    d->field[j].list_next = d->field[i].list_next;
	    d->field[i].list_next = d->hash[h];
	    d->hash[h] = i;
	 }
	 return &(d->field[i].entry);
      }
   }
   return NULL;
}

/*
 * Delete an entry from the quere and the hash.
 */
static void
queue_delete(queue_t * d, uint16_t entry) {
   uint16_t h, i, j=0;

   INSIST(d != NULL);
   RUNTIME_CHECK(0 < entry && entry < d->length);
   h = queue_makehash(d, &d->field[entry].entry.netaddr);
   INSIST(h < d->length);
   
   for(i = d->hash[h]; i != entry; i = d->field[j=i].list_next) {
      INSIST(0 < i && i < d->length);
   }
   
   /* Remove from hash */
   if(j>0)
     d->field[j].list_next = d->field[i].list_next;
   else
     d->hash[h] = d->field[i].list_next;
   
   /* Remove from queue */
   d->field[d->field[i].queue_next].queue_prev = d->field[i].queue_prev;
   d->field[d->field[i].queue_prev].queue_next = d->field[i].queue_next;

   /* Back to free space */
   d->field[i].list_next = QUEUE_AVAIL(d);
   QUEUE_AVAIL(d) = i;
}

/*
 * Recalculate the penaly by expotential decay and new points. If the new
 * penalty is high enough, move it to the front of the queue, otherwise
 * remove it completely.
 */
static void
queue_update(void * data, dns_dampening_entry_t ** entry, uint16_t points, isc_stdtime_t now) {
   queue_t * d = data;
   uint16_t e;
   
   INSIST(data != NULL);
   INSIST(entry != NULL);
   e = (queue_entry_t*)*entry - d->field;
   RUNTIME_CHECK(0 < e && e < d->length);
   
   if(update_penalty(d->conf, *entry, points, now) == 0)
     queue_delete(d, e);
   else if(QUEUE_FRONT(d) != e) {
      /* Move to front */
      d->field[e].queue_prev = d->field[QUEUE_FRONT(d)].queue_prev;
      d->field[QUEUE_FRONT(d)].queue_prev = e;
      d->field[e].queue_next = QUEUE_FRONT(d);
      QUEUE_FRONT(d) = e;
   }
}

/*
 * Add a new element by inserting it into the front of the hash list
 * and the decay queue. Recalculate the oldest element to get free space
 * if necessary.
 */
static void
queue_add(void * data, const isc_netaddr_t * netaddr,
	  uint16_t points, isc_stdtime_t now) {
   queue_t * d = data;
   uint16_t n, h = queue_makehash(data,netaddr);

   INSIST(data != NULL);
   INSIST(h < d->length);
   
   if(QUEUE_AVAIL(d) == 0) {   /* full */
      dns_dampening_entry_t * e;
      
      /* Check against least used element */
      INSIST(QUEUE_REAR(d) != 0);
      e = &(d->field[QUEUE_REAR(d)].entry);
      update_penalty(d->conf, e, 0, now);

      if(e->penalty > points) {
	 queue_update(d, &e, 0, now);
	 return;
      } else 
	queue_delete(d, QUEUE_REAR(d));
   }
   
   INSIST(QUEUE_AVAIL(d) != 0);
   
   /* Allocate n */
   n = QUEUE_AVAIL(d);
   QUEUE_AVAIL(d) = d->field[n].list_next;
   
   /* Link to hash */
   d->field[n].list_next = d->hash[h];
   d->hash[h] = n;
   
   /* Place in front */
   d->field[n].queue_prev = d->field[QUEUE_FRONT(d)].queue_prev;
   d->field[QUEUE_FRONT(d)].queue_prev = n;
   d->field[n].queue_next = QUEUE_FRONT(d);
   QUEUE_FRONT(d) = n;
   
   /* Setup */
   memset(&d->field[n].entry, 0, sizeof(d->field[n].entry));
   memcpy(&d->field[n].entry.netaddr, netaddr, sizeof(d->field[n].entry.netaddr));
   d->field[n].entry.penalty       = points;
   d->field[n].entry.last_updated  = now;
}

/*
 * Free the memory for this data structure.
 */
static void
queue_destroy(void ** pdata) {
   
   INSIST(pdata != NULL);
   if(*pdata != NULL) {
      queue_t * d = *pdata;

      if(d->hash != NULL)
	isc_mem_put(d->mctx, d->hash, d->length * sizeof(*(d->hash)));
      
      if(d->field != NULL)
	isc_mem_put(d->mctx, d->field, d->length * sizeof(*(d->field)));
      
      isc_mem_put(d->mctx, d, sizeof(*d));
      *pdata = NULL;
   }
   
   INSIST(*pdata == NULL);
}

/*
 * Allocate the memory for this data structure.
 */
isc_result_t queue_init(isc_mem_t * mctx, dns_dampening_implementation_t * impl,
			dns_dampening_t * conf, uint16_t size) {
   queue_t * d;
   int i;
   
   INSIST(mctx != NULL);
   INSIST(impl != NULL);
   INSIST(size > 0);

   impl->destroy = queue_destroy;
   
   impl->data = d = isc_mem_get(mctx, sizeof(*d));
   if(d == NULL)
          return ISC_R_NOMEMORY;
   memset(d, 0, sizeof(*d));
   
   d->length = size+1;
   d->field = isc_mem_get(mctx, d->length * sizeof(*(d->field)));
   d->hash  = isc_mem_get(mctx, d->length * sizeof(*(d->hash)));
   d->mctx = mctx;
   d->conf = conf;
   if(d->field == NULL || d->hash == NULL) {
      impl->destroy(&impl->data);
      return ISC_R_NOMEMORY;
   }
   
   /* Initialize free space */
   for(i=0; i < d->length - 1; i++) {
      d->field[i].list_next = i+1;
      d->hash[i] = 0;
   }
   /* last element */
   d->field[i].list_next = 0;
   d->hash[i] = 0;

   /* Sentiel values */
   QUEUE_FRONT(d) = QUEUE_REAR(d) = 0;
   QUEUE_AVAIL(d) = 1;
   
   
   impl->search  = queue_search;
   impl->add     = queue_add;
   impl->update  = queue_update;
   
   isc_log_write(dns_lctx, DNS_LOGCATEGORY_DAMPENING,
		 DNS_LOGMODULE_REQUEST, ISC_LOG_INFO,
		 "Queue initialized to %d entries and %d hash: %u bytes",
		 size, size+1,
		 (sizeof(*d->hash)+sizeof(*d->field))*(1+size));
   return ISC_R_SUCCESS;
}
