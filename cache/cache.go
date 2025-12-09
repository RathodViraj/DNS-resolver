package cache

import (
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type cachedEntry struct {
	msg    *dnsmessage.Message
	expiry time.Time
}

type Cache struct {
	queries map[string]cachedEntry
	ns      map[string]cachedEntry
	cname   map[string]cachedEntry
	tld     map[string]cachedEntry
	lock    sync.RWMutex
}

var store = &Cache{
	queries: make(map[string]cachedEntry),
	ns:      make(map[string]cachedEntry),
	cname:   make(map[string]cachedEntry),
	tld:     make(map[string]cachedEntry),
}

func StartPeriodicCleanup() {
	ticker := time.NewTicker(12 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		cleanupExpiredEntries()
	}
}

func cleanupExpiredEntries() {
	now := time.Now()

	store.lock.Lock()
	for k, v := range store.queries {
		if now.After(v.expiry) {
			delete(store.queries, k)
		}
	}
	store.lock.Unlock()

	store.lock.Lock()
	for k, v := range store.ns {
		if now.After(v.expiry) {
			delete(store.ns, k)
		}
	}
	store.lock.Unlock()

	store.lock.Lock()
	for k, v := range store.cname {
		if now.After(v.expiry) {
			delete(store.cname, k)
		}
	}
	store.lock.Unlock()

	store.lock.Lock()
	for k, v := range store.tld {
		if now.After(v.expiry) {
			delete(store.tld, k)
		}
	}
	store.lock.Unlock()
}

func cacheKey(name dnsmessage.Name, qtype dnsmessage.Type) string {
	return name.String() + "|" + qtype.String()
}

func GetFromCache(name dnsmessage.Name, qtype dnsmessage.Type) (*dnsmessage.Message, string, bool) {
	key := cacheKey(name, qtype)
	now := time.Now()

	store.lock.RLock()
	if e, ok := store.queries[key]; ok {
		if now.Before(e.expiry) {
			store.lock.RUnlock()
			return e.msg, "queries", true
		} else {
			store.lock.RUnlock()
			store.lock.Lock()
			delete(store.queries, key)
			store.lock.Unlock()
			return nil, "", false
		}
	}

	if qtype == dnsmessage.TypeNS {
		if e, ok := store.ns[key]; ok {
			if now.Before(e.expiry) {
				store.lock.RUnlock()
				return e.msg, "ns", true
			} else {
				store.lock.RUnlock()
				store.lock.Lock()
				delete(store.ns, key)
				store.lock.Unlock()
				return nil, "", false
			}
		}
		if e, ok := store.tld[key]; ok {
			if now.Before(e.expiry) {
				store.lock.RUnlock()
				return e.msg, "tld", true
			} else {
				store.lock.RUnlock()
				store.lock.Lock()
				delete(store.tld, key)
				store.lock.Unlock()
				return nil, "", false
			}
		}
	}

	if qtype != dnsmessage.TypeCNAME {
		cnameKey := cacheKey(name, dnsmessage.TypeCNAME)
		if e, ok := store.cname[cnameKey]; ok {
			if now.Before(e.expiry) {
				store.lock.RUnlock()
				return e.msg, "cname", true
			} else {
				store.lock.RUnlock()
				store.lock.Lock()
				delete(store.cname, cnameKey)
				store.lock.Unlock()
				return nil, "", false
			}
		}
	}

	store.lock.RUnlock()

	return nil, "", false
}

func SaveToCache(name dnsmessage.Name, qtype dnsmessage.Type, msg *dnsmessage.Message, ttl uint32) {
	key := cacheKey(name, qtype)
	expiry := time.Now().Add(time.Duration(ttl) * time.Second)

	store.lock.Lock()
	defer store.lock.Unlock()

	entry := cachedEntry{msg: msg, expiry: expiry}

	switch qtype {
	case dnsmessage.TypeNS:
		store.ns[key] = entry
		labels := strings.Count(name.String(), ".")
		if labels <= 1 {
			store.tld[key] = entry
		}
	case dnsmessage.TypeCNAME:
		store.cname[key] = entry
	default:
		store.queries[key] = entry
	}
}
