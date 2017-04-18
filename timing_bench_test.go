package httpseverywhere

import (
	"math"
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

func (h *accumulator) addTimingNotLocked(host string, dur time.Duration) {
	ms := dur.Nanoseconds() / int64(time.Millisecond)
	h.stats.runs++
	h.stats.totalTime += ms
	if ms > h.stats.max {
		h.stats.max = ms
		h.stats.maxHost = host
	}

	h.log.Debugf("Average running time: %vms", float64(h.stats.totalTime/h.stats.runs))
	h.log.Debugf("Max running time: %vms for host: %v", h.stats.max, h.stats.maxHost)
}

func BenchmarkChannel(b *testing.B) {
	h := &accumulator{log: golog.LoggerFor("channel"), stats: &httpseStats{}}
	ch := make(chan *timing)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		for i := 0; i < b.N; i++ {
			t := <-ch
			h.addTimingNotLocked(t.host, t.dur)
		}
		wg.Done()
	}()

	for i := 0; i < concurrency; i++ {
		dur := time.Duration(i+1) * time.Second
		go func() {
			for j := 0; j < int(math.Ceil(float64(b.N)/concurrency)); j++ {
				ch <- &timing{host: "myhost", dur: dur}
			}
		}()
	}

	b.ResetTimer()
	wg.Wait()
}

func BenchmarkLock(b *testing.B) {
	h := &accumulator{log: golog.LoggerFor("channel"), stats: &httpseStats{}}

	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		dur := time.Duration(i+1) * time.Second
		go func() {
			for j := 0; j < int(math.Ceil(float64(b.N)/concurrency)); j++ {
				h.addTimingLocked("myhost", dur)
			}
			wg.Done()
		}()
	}

	b.ResetTimer()
	wg.Wait()
}
