# Optimized ring buffer algorithm

Note: this folder exists only in the agent-libs fork and contains an optimized algorithm for scraping ring buffers. It is based on a sorted linked list algorithm + a cache mechanism.

## Some notes

- The actual supported drivers are `modern_ebpf`, `ebpf`, `kmod`. Udig at the moment is not supported since it has a dynamic mechanism to add/remove new buffers at runtime.
- This algorithm can handle offline CPUs, so it works well if a startup time CPU 1 is offline for example. This is because we use buffer IDs rather than CPU IDs. So our buffer IDs will be always contiguous even if some CPUs are offline.
- Today we don't support CPU hotplug at runtime in the above drivers. In case of a CPU hotplug we send an event to userspace and we throw an exception, in this way our agent will restart with the new number of CPUs.

## Out-of-order events

### legacy_ebpf/kmod

The reason why we scrape out-of-order events in these 2 drivers is that we store a buffer block for each device and we read only from it. Let's imagine the following example

```text
BUF0  BUF1  BUF2  BUF3
 1     7     10    11   --> These numbers are the event timestamps
 2     8     -     -    --> This is the end of the buffer block we store
 3     9     13    16
 4     -     14
 -     12    15
 5
 6

```

As you can see for `BUF0` we take a block that contains only 4 events with timestamps (1,2,3,4) but we don't take the following events with timestamps (5,6). This means after the event with timestamp `4` we will read the event with timestamp `7` and not the one with timestamp `5` because it is out of our saved blocks.

This is true both for the default algorithm and for the optimized one. There are no known differences between the 2 algorithms with out-of-order events.

### modern_ebpf

In the modern ebpf probe we don't store buffer blocks but we face other possible issues. It is convenient to analyze different scenarios separately

#### 1 Buffer for each CPU

If we don't consider page faults (usually disabled) it is possible only one race condition in this scenario: a buffer is empty when we scrape it but immediately after it receives an event with a lower timestamp than other events in the following buffers.

Let's imagine the following example:

```text
-- Time 0: We are iterating over the buffers. BUF0 has no event.

BUF0  BUF1  BUF2  BUF3
 -     2     3     -   
 ^

-- Time 1: While we are iterating (let's say we are on BUF1), a new event arrives on BUF0 with timestamp 1. This is possible since the event on BUF0 could have required more time in the instrumentation kernel side. 

BUF0  BUF1  BUF2  BUF3
 1     2     3     -   
       ^

-- Time 2: We continue to iterate (let's say we are on BUF2) and a new event arrives on BUF3.

BUF0  BUF1  BUF2  BUF3
 1     2     3     4   
             ^
```

This means that the return of scap-next will be the event with timestamp 2. Only at the following `scap-next`, we will take the event with timestamp 1, but it is too late.

Please note that there is a difference between the default algorithm and the optimized one. In the default algorithm, we will take the event with timestamp 1 at the following `scap-next` as stated above. With the optimized one we will exclude the BUF0 from the active list (`2->3->4`), and we will consider it again only when the active list becomes empty.

Important to note that with both algorithms, in this scenario, we shouldn't receive out-of-order events on the same buffer! Even more important we shouldn't receive out-of-order events on the same thread-id!

If we write some tests we can see that this kind of race condition happens at every run. This is a concrete example with the default algorithm:

```text
///////////////////////////////////////////// FIRST ITERATION

Iterate over all the buffers
[NULL Event] buf: 0
[Event] ts: 1723544937406537346, buf: 1
Found new min with ts '1723544937406537346'  on buffer 1
[NULL Event] buf: 2
[NULL Event] buf: 3
[NULL Event] buf: 4
[NULL Event] buf: 5
[NULL Event] buf: 6
[NULL Event] buf: 7
[NULL Event] buf: 8
[NULL Event] buf: 9
[NULL Event] buf: 10
[NULL Event] buf: 11
[NULL Event] buf: 12
[NULL Event] buf: 13
[NULL Event] buf: 14
[Event] ts: 1723544937405825865, buf: 15
Found new min with ts '1723544937405825865'  on buffer 15
Send event -> [Event] ts: 1723544937405825865, buf: 15

-> BUF 15 has the lowest timestamp

///////////////////////////////////////////// SECOND ITERATION

Iterate over all the buffers
[NULL Event] buf: 0
[Event] ts: 1723544937406537346, buf: 1
Found new min with ts '1723544937406537346'  on buffer 1
[NULL Event] buf: 2
[NULL Event] buf: 3
[NULL Event] buf: 4
[NULL Event] buf: 5
[NULL Event] buf: 6
[NULL Event] buf: 7
[Event] ts: 1723544937405435656, buf: 8
Found new min with ts '1723544937405435656'  on buffer 8
[NULL Event] buf: 9
[NULL Event] buf: 10
[NULL Event] buf: 11
[NULL Event] buf: 12
[NULL Event] buf: 13
[NULL Event] buf: 14
[Event] ts: 1723544937405827416, buf: 15
Send event -> [Event] ts: 1723544937405827416, buf: 8
[Prev] ts(1723544937405825865) buf(15) >  [Curr] ts(1723544937405435656) buf(8)

-> We face an event on BUF 8 that has a lower timestamp than the previous one on buf 15
```

If page faults are enabled we can face out-of-order events also on the same buffer. What happens is that the current thread that is running an ebpf program, calls our page fault ebpf program in the middle and will send the page fault event to userspace before the current event it was processing. So we will see the page fault event with a greater timestamp, before the original event (with a lower timestamp) in the same buffer. This typically happens during an `open` syscall when a page fault is triggered reading the userspace memory. We will see the page fault event before the open_e event in the buffer.

#### 1 Buffer for each 2 CPUs (default)

In this scenario, we have the same race condition described above, but we also have another case.

```text
   BUF0
  ^    ^
  |    |
CPU0  CPU1
  1    2
```

1. Let's say CPU0 generates an event with timestamp 1, it stores it in its internal auxiliary map and starts the collection of its parameter.
2. In the meanwhile, CPU1 generates an event with timestamp 2, but in this case, the space is immediately reserved in the ring buffer with the `ringbuf_reserve()` approach. So CPU0 is using the auxiliary map while CPU1 is directly reserving memory in the ring buffer.
3. Only after some time, CPU0 will copy the content of the auxiliary map inside the buffer but this event will be pushed AFTER the CPU1 one, even if it has a lower timestamp. CPU1 reserved the memory for its event before CPU0.

This will cause out-of-order events in the same buffer.

> __Please note__: This means that with the optimized algorithm is possible that events belonging to the same thread will come out of order. If the flow of thread events is interrupted by an event with a higher timestamp, coming from another CPU, the buffer could be excluded from the active list even if it still contains events with low timestamps. This shouldn't be a frequent case but we need to keep it into consideration.

So in this scenario, we have 2 possible out-of-order conditions:

1. Out-of-order events on the same buffer.
2. Out-of-order events on different buffers (described in the previous scenario).

#### 1 Buffer for all CPUs

In this case, we cannot have out-of-order events between different buffers since the buffer is just one, so we just have out-of-order events on the same buffer. This scenario is not used in production at the moment due to the high kernel contention.
