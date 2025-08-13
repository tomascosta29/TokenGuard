package handler

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// IPRateLimiter stores a rate limiter for each IP address.
type IPRateLimiter struct {
	ips map[string]*visitor
	mu  *sync.RWMutex
	r   rate.Limit
	b   int
}

// visitor represents a client with a rate limiter and last seen time.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewIPRateLimiter creates a new IPRateLimiter.
func NewIPRateLimiter(r rate.Limit, b int) *IPRateLimiter {
	i := &IPRateLimiter{
		ips: make(map[string]*visitor),
		mu:  &sync.RWMutex{},
		r:   r,
		b:   b,
	}

	go i.cleanupVisitors()
	return i
}

// AddVisitor creates a new rate limiter for a given IP address.
func (i *IPRateLimiter) AddVisitor(ip string) *rate.Limiter {
	limiter := rate.NewLimiter(i.r, i.b)
	i.mu.Lock()
	defer i.mu.Unlock()

	i.ips[ip] = &visitor{limiter, time.Now()}
	return limiter
}

// GetVisitor returns the rate limiter for a given IP address.
func (i *IPRateLimiter) GetVisitor(ip string) *rate.Limiter {
	i.mu.RLock()
	v, exists := i.ips[ip]
	i.mu.RUnlock()

	if !exists {
		return i.AddVisitor(ip)
	}

	v.lastSeen = time.Now()
	return v.limiter
}

// cleanupVisitors removes old entries from the ips map.
func (i *IPRateLimiter) cleanupVisitors() {
	for {
		time.Sleep(1 * time.Minute)

		i.mu.Lock()
		for ip, v := range i.ips {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(i.ips, ip)
			}
		}
		i.mu.Unlock()
	}
}

// RateLimitMiddleware is a middleware that applies rate limiting to requests.
func RateLimitMiddleware(limiter *IPRateLimiter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				respondWithError(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}

			if !limiter.GetVisitor(ip).Allow() {
				respondWithError(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
