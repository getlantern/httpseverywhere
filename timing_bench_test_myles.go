package httpseverywhere

import (
	"sync"
	"testing"
	"time"

	"github.com/getlantern/golog"
)

const concurrency = 1000

type accumulator struct {
	log   golog.Logger
	stats *httpseStats
	mx    sync.Mutex
}

func (h *accumulator) addTimingLocked(host string, dur time.Duration) {
	h.mx.Lock()
	ms := dur.Nanoseconds() / int64(time.Millisecond)
	h.stats.runs++
	h.stats.totalTime += ms
	if ms > h.stats.max {
		h.stats.max = ms
		h.stats.maxHost = host
	}
	runs, totalTime, max, maxHost := h.stats.runs, h.stats.totalTime, h.stats.max, h.stats.maxHost
	h.mx.Unlock()

	h.log.Debugf("Average running time: %vms", float64(totalTime/runs))
	h.log.Debugf("Max running time: %vms for host: %v", max, maxHost)
}

func BenchmarkChannel(b *testing.B) {
	ch := make(chan *timing)
	go func() {
		for {
			<-ch
		}
	}()
	dur := time.Duration(10)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	b.ResetTimer()
	for i := 0; i < concurrency; i++ {
		go func() {
			ch <- &timing{host: "myhost", dur: dur}
			wg.Done()
		}()
	}
	wg.Wait()
}

func BenchmarkLock(b *testing.B) {
	h := &accumulator{log: golog.LoggerFor("channel"), stats: &httpseStats{}}

	dur := time.Duration(10)
	var wg sync.WaitGroup
	wg.Add(concurrency)

	b.ResetTimer()
	for i := 0; i < concurrency; i++ {
		go func() {
			h.addTimingLocked("myhost", dur)
			wg.Done()
		}()
	}
	wg.Wait()
}
