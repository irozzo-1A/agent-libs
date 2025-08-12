# Deadlock Prevention Guide for Thread Safety Implementation

## Overview

This document outlines the deadlock prevention strategies implemented in the thread safety system for `sinsp_thread_manager` and `sinsp_threadinfo` classes.

## Deadlock Scenarios Identified

### 1. **Nested Lock Acquisition Deadlocks**

**Problem**: Multiple locks acquired in different orders by different threads.

**Example**:
```cpp
// Thread A
void clear() {
    std::unique_lock<std::shared_mutex> lock1(m_threadtable_mutex);  // Lock A
    std::unique_lock<std::shared_mutex> lock2(m_thread_groups_mutex); // Lock B
}

// Thread B  
void remove_thread() {
    std::unique_lock<std::shared_mutex> lock2(m_thread_groups_mutex); // Lock B
    std::unique_lock<std::shared_mutex> lock1(m_threadtable_mutex);   // Lock A
}
```

**Result**: Deadlock when both threads execute simultaneously.

### 2. **Cross-Class Lock Deadlocks**

**Problem**: Locks acquired across different classes in different orders.

**Example**:
```cpp
// Thread A: Thread Manager -> Thread Info
thread_manager->add_thread(...);  // Acquires thread_manager lock
thread_info->add_child(...);      // Acquires thread_info lock

// Thread B: Thread Info -> Thread Manager  
thread_info->remove_child_from_parent(); // Acquires thread_info lock
thread_manager->remove_thread(...);       // Acquires thread_manager lock
```

### 3. **Recursive Lock Deadlocks**

**Problem**: Same lock acquired multiple times by the same thread.

**Example**:
```cpp
void method1() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    method2(); // Tries to acquire same lock again
}

void method2() {
    std::unique_lock<std::shared_mutex> lock(m_mutex); // Deadlock!
}
```

## Deadlock Prevention Strategies

### 1. **Consistent Lock Ordering**

**Principle**: Always acquire locks in the same predefined order.

**Implementation**:
```cpp
enum class LockOrder {
    THREADTABLE = 1,      // Highest priority
    THREAD_GROUPS = 2,
    CACHE = 3,
    STATS = 4,
    CONFIG = 5,
    FLUSH = 6,
    FOREIGN_FIELDS = 7,
    FOREIGN_TABLES = 8,
    SERVER_PORTS = 9      // Lowest priority
};
```

**Usage**:
```cpp
void clear() {
    // Always acquire in order: THREADTABLE -> THREAD_GROUPS -> CACHE -> STATS -> FLUSH
    std::unique_lock<std::shared_mutex> threadtable_lock(m_threadtable_mutex);
    std::unique_lock<std::shared_mutex> groups_lock(m_thread_groups_mutex);
    std::unique_lock<std::mutex> cache_lock(m_cache_mutex);
    std::unique_lock<std::mutex> stats_lock(m_stats_mutex);
    std::unique_lock<std::mutex> flush_lock(m_flush_mutex);
    
    // Perform operations...
    // Locks automatically released in reverse order
}
```

### 2. **Lock Hierarchy Rules**

**Rule 1**: Thread Manager locks have higher priority than Thread Info locks
**Rule 2**: Within Thread Manager, follow the LockOrder enum
**Rule 3**: Never acquire Thread Info locks while holding Thread Manager locks

**Implementation**:
```cpp
// CORRECT: Thread Manager -> Thread Info
void add_thread() {
    std::unique_lock<std::shared_mutex> lock(m_threadtable_mutex);
    // ... thread manager operations ...
    
    // Release thread manager lock before accessing thread info
    lock.unlock();
    
    // Now safe to access thread info
    thread_info->add_child(child);
}

// INCORRECT: Thread Info -> Thread Manager (potential deadlock)
void thread_info_method() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    // ... thread info operations ...
    
    // DANGEROUS: Acquiring thread manager lock while holding thread info lock
    thread_manager->remove_thread(tid); // Potential deadlock!
}
```

### 3. **Lock-Free Operations**

**Principle**: Minimize lock scope and use lock-free operations where possible.

**Examples**:
```cpp
// GOOD: Minimal lock scope
void get_thread_count() {
    std::shared_lock<std::shared_mutex> lock(m_threadtable_mutex);
    return m_threadtable.size(); // Lock released immediately
}

// BETTER: Lock-free for simple operations
void increment_counter() {
    // Use atomic operations instead of locks for simple counters
    m_counter.fetch_add(1, std::memory_order_relaxed);
}
```

### 4. **RAII Lock Management**

**Principle**: Use RAII (Resource Acquisition Is Initialization) for automatic lock management.

**Implementation**:
```cpp
class LockGuard {
public:
    LockGuard(std::shared_mutex& mutex, LockOrder order, bool write = false) 
        : m_mutex(mutex), m_order(order), m_write(write) {
        if (m_write) {
            m_unique_lock = std::make_unique<std::unique_lock<std::shared_mutex>>(m_mutex);
        } else {
            m_shared_lock = std::make_unique<std::shared_lock<std::shared_mutex>>(m_mutex);
        }
    }
    
    // Destructor automatically releases lock
    ~LockGuard() = default;

private:
    std::shared_mutex& m_mutex;
    LockOrder m_order;
    bool m_write;
    std::unique_ptr<std::unique_lock<std::shared_mutex>> m_unique_lock;
    std::unique_ptr<std::shared_lock<std::shared_mutex>> m_shared_lock;
};
```

## Best Practices

### 1. **Lock Acquisition Patterns**

```cpp
// Pattern 1: Single lock
void simple_operation() {
    std::shared_lock<std::shared_mutex> lock(m_mutex);
    // Perform read-only operation
}

// Pattern 2: Multiple locks in order
void complex_operation() {
    std::unique_lock<std::shared_mutex> lock1(m_mutex1);
    std::unique_lock<std::mutex> lock2(m_mutex2);
    std::unique_lock<std::mutex> lock3(m_mutex3);
    // Perform operations
}

// Pattern 3: Conditional locking
void conditional_operation() {
    {
        std::shared_lock<std::shared_mutex> lock(m_mutex);
        if (!needs_write) {
            return; // Lock released early
        }
    }
    
    // Need write access
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    // Perform write operation
}
```

### 2. **Avoiding Common Pitfalls**

**Pitfall 1: Lock Ordering Violations**
```cpp
// WRONG: Inconsistent lock order
void method1() {
    std::unique_lock<std::mutex> lock1(m_mutex1);
    std::unique_lock<std::mutex> lock2(m_mutex2);
}

void method2() {
    std::unique_lock<std::mutex> lock2(m_mutex2); // Different order!
    std::unique_lock<std::mutex> lock1(m_mutex1);
}

// RIGHT: Consistent lock order
void method1() {
    std::unique_lock<std::mutex> lock1(m_mutex1);
    std::unique_lock<std::mutex> lock2(m_mutex2);
}

void method2() {
    std::unique_lock<std::mutex> lock1(m_mutex1); // Same order
    std::unique_lock<std::mutex> lock2(m_mutex2);
}
```

**Pitfall 2: Holding Locks Too Long**
```cpp
// WRONG: Lock held during expensive operation
void expensive_operation() {
    std::unique_lock<std::mutex> lock(m_mutex);
    // ... expensive computation ...
    // Lock held unnecessarily long
}

// RIGHT: Minimal lock scope
void expensive_operation() {
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        // ... quick data access ...
    } // Lock released
    
    // ... expensive computation without lock ...
    
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        // ... update results ...
    }
}
```

**Pitfall 3: Recursive Lock Acquisition**
```cpp
// WRONG: Same lock acquired multiple times
void outer_method() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    inner_method(); // Tries to acquire same lock
}

void inner_method() {
    std::unique_lock<std::shared_mutex> lock(m_mutex); // Deadlock!
}

// RIGHT: Pass lock or use different synchronization
void outer_method() {
    std::unique_lock<std::shared_mutex> lock(m_mutex);
    inner_method(lock); // Pass existing lock
}

void inner_method(std::unique_lock<std::shared_mutex>& lock) {
    // Use existing lock, don't acquire new one
}
```

## Testing Deadlock Prevention

### 1. **Concurrent Access Tests**

```cpp
TEST(ThreadSafetyTest, ConcurrentAddRemove) {
    std::vector<std::thread> threads;
    
    // Start multiple threads adding and removing threads
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back([&]() {
            for (int j = 0; j < 100; ++j) {
                auto thread = std::make_unique<sinsp_threadinfo>(params);
                thread_manager->add_thread(std::move(thread), false);
                thread_manager->remove_thread(j);
            }
        });
    }
    
    // Wait for all threads to complete
    for (auto& thread : threads) {
        thread.join();
    }
    
    // Verify no deadlocks occurred
    EXPECT_TRUE(true); // If we reach here, no deadlock occurred
}
```

### 2. **Lock Ordering Tests**

```cpp
TEST(ThreadSafetyTest, LockOrdering) {
    std::atomic<bool> deadlock_detected{false};
    
    // Thread A: clear() method
    std::thread thread_a([&]() {
        try {
            thread_manager->clear();
        } catch (...) {
            deadlock_detected = true;
        }
    });
    
    // Thread B: remove_thread() method
    std::thread thread_b([&]() {
        try {
            thread_manager->remove_thread(123);
        } catch (...) {
            deadlock_detected = true;
        }
    });
    
    thread_a.join();
    thread_b.join();
    
    EXPECT_FALSE(deadlock_detected.load());
}
```

### 3. **Stress Testing**

```cpp
TEST(ThreadSafetyTest, StressTest) {
    const int num_threads = 20;
    const int operations_per_thread = 1000;
    
    std::vector<std::thread> threads;
    std::atomic<int> completed_operations{0};
    
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&, i]() {
            for (int j = 0; j < operations_per_thread; ++j) {
                // Mix of different operations
                switch (j % 4) {
                    case 0:
                        thread_manager->get_thread_ref(i * 1000 + j, false);
                        break;
                    case 1:
                        thread_manager->get_thread_count();
                        break;
                    case 2:
                        thread_manager->set_max_thread_table_size(100000);
                        break;
                    case 3:
                        thread_manager->reset_thread_counters();
                        break;
                }
                completed_operations.fetch_add(1);
            }
        });
    }
    
    for (auto& thread : threads) {
        thread.join();
    }
    
    EXPECT_EQ(completed_operations.load(), num_threads * operations_per_thread);
}
```

## Monitoring and Debugging

### 1. **Deadlock Detection Tools**

- **Thread Sanitizer**: `-fsanitize=thread`
- **Helgrind**: Valgrind's thread error detector
- **Custom deadlock detection**: Timeout-based detection

### 2. **Lock Contention Monitoring**

```cpp
class LockMetrics {
public:
    void record_lock_acquired(LockOrder order) {
        m_lock_counts[static_cast<size_t>(order)]++;
        m_last_acquired = std::chrono::steady_clock::now();
    }
    
    void record_lock_released(LockOrder order) {
        auto duration = std::chrono::steady_clock::now() - m_last_acquired;
        m_lock_durations[static_cast<size_t>(order)] += duration;
    }
    
    void print_metrics() {
        for (size_t i = 0; i < static_cast<size_t>(LockOrder::SERVER_PORTS) + 1; ++i) {
            std::cout << "Lock " << i << ": " 
                      << m_lock_counts[i] << " acquisitions, "
                      << std::chrono::duration_cast<std::chrono::microseconds>(
                          m_lock_durations[i]).count() << " us total\n";
        }
    }

private:
    std::array<std::atomic<uint64_t>, 10> m_lock_counts{};
    std::array<std::chrono::steady_clock::duration, 10> m_lock_durations{};
    std::chrono::steady_clock::time_point m_last_acquired;
};
```

## Conclusion

The deadlock prevention strategy relies on:

1. **Consistent lock ordering** across all methods
2. **Minimal lock scope** to reduce contention
3. **Clear hierarchy** between different lock types
4. **RAII lock management** for automatic cleanup
5. **Comprehensive testing** to verify deadlock prevention

By following these guidelines, the thread safety implementation provides robust protection against deadlocks while maintaining good performance characteristics.
