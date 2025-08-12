# Thread Safety Implementation for Thread Manager and Sinsp Thread

## Overview

This document describes the thread safety implementation for the `sinsp_thread_manager` and `sinsp_threadinfo` classes in the Falco libsinsp library. The implementation uses C++ standard library mutexes to ensure thread-safe access to shared data structures.

## Key Components

### 1. Thread Manager (`sinsp_thread_manager`)

#### Mutex Types Used
- **`std::shared_mutex`**: For read-write access patterns where reads are more frequent than writes
- **`std::mutex`**: For exclusive access to data that is primarily written

#### Protected Data Structures

| Data Structure | Mutex Type | Purpose |
|----------------|------------|---------|
| `m_threadtable` | `std::shared_mutex` | Main thread table (read-heavy) |
| `m_thread_groups` | `std::shared_mutex` | Thread group mappings |
| `m_last_tid`, `m_last_tinfo` | `std::mutex` | Thread lookup cache |
| `m_n_proc_lookups`, etc. | `std::mutex` | Statistics counters |
| `m_max_thread_table_size`, etc. | `std::mutex` | Configuration parameters |
| `m_last_flush_time_ns` | `std::mutex` | Flush timing |
| `m_foreign_fields_accessors` | `std::mutex` | Plugin field accessors |
| `m_foreign_tables` | `std::mutex` | Plugin tables |
| `m_server_ports` | `std::mutex` | Server port tracking |

#### Critical Methods Made Thread-Safe

1. **`add_thread()`**: Protected thread table insertion
2. **`remove_thread()`**: Protected thread removal and cleanup
3. **`find_thread()`**: Protected thread lookup with caching
4. **`get_thread_ref()`**: Protected thread reference retrieval
5. **`clear()`**: Protected table clearing
6. **`get_thread_count()`**: Protected size queries
7. **Configuration methods**: Protected parameter updates

### 2. Thread Info (`sinsp_threadinfo`)

#### Mutex Type
- **`std::shared_mutex`**: Single mutex protecting all mutable state

#### Protected Operations

| Operation | Lock Type | Purpose |
|-----------|-----------|---------|
| `add_child()` | `std::unique_lock` | Add child thread |
| `remove_child_from_parent()` | `std::unique_lock` | Remove child thread |
| `clean_expired_children()` | `std::unique_lock` | Cleanup expired children |
| `set_cwd()` | `std::unique_lock` | Update working directory |
| `set_dead()` | `std::unique_lock` | Mark thread as dead |
| `resurrect_thread()` | `std::unique_lock` | Mark thread as alive |
| `set_parent_loop_detected()` | `std::unique_lock` | Set parent loop flag |
| `set_lastevent_*()` | `std::unique_lock` | Update event state |
| `parent_loop_detected()` | `std::shared_lock` | Read parent loop flag |

### 3. Thread Table (`threadinfo_map_t`)

#### Mutex Type
- **`std::shared_mutex`**: Protects the underlying `std::unordered_map`

#### Protected Operations

| Operation | Lock Type | Purpose |
|-----------|-----------|---------|
| `put()` | `std::unique_lock` | Insert thread |
| `get()` | `std::shared_lock` | Lookup thread |
| `get_ref()` | `std::shared_lock` | Get thread reference |
| `erase()` | `std::unique_lock` | Remove thread |
| `clear()` | `std::unique_lock` | Clear table |
| `size()` | `std::shared_lock` | Get table size |
| `loop()` methods | `std::shared_lock` | Iterate over threads |

## Thread Safety Patterns

### 1. Read-Write Lock Pattern
Used for data structures that are read frequently but written occasionally:
```cpp
// Read operation
std::shared_lock<std::shared_mutex> lock(m_mutex);
auto result = m_data.find(key);

// Write operation
std::unique_lock<std::shared_mutex> lock(m_mutex);
m_data[key] = value;
```

### 2. Exclusive Lock Pattern
Used for data that is primarily written or requires exclusive access:
```cpp
std::unique_lock<std::mutex> lock(m_mutex);
m_counter++;
```

### 3. Nested Lock Pattern
Used when multiple data structures need to be protected:
```cpp
{
    std::shared_lock<std::shared_mutex> lock1(m_mutex1);
    std::unique_lock<std::mutex> lock2(m_mutex2);
    // Operations on both structures
}
```

## Performance Considerations

### 1. Lock Granularity
- **Fine-grained**: Separate mutexes for different data structures
- **Read-write locks**: Allow concurrent reads while protecting writes
- **Minimal critical sections**: Lock only when necessary

### 2. Lock Ordering
To prevent deadlocks, locks are acquired in a consistent order:
1. `m_threadtable_mutex` (if needed)
2. `m_thread_groups_mutex` (if needed)
3. `m_cache_mutex`
4. `m_stats_mutex`
5. `m_config_mutex`
6. Other mutexes

### 3. Lock-Free Operations
Some operations remain lock-free for performance:
- Read-only access to immutable data
- Atomic operations on simple types
- Local variable modifications

## Usage Guidelines

### 1. For Thread Manager Users
```cpp
// Thread-safe thread lookup
auto thread = thread_manager->get_thread_ref(tid, true);

// Thread-safe thread addition
auto new_thread = std::make_unique<sinsp_threadinfo>(params);
thread_manager->add_thread(std::move(new_thread), false);

// Thread-safe thread removal
thread_manager->remove_thread(tid);
```

### 2. For Thread Info Users
```cpp
// Thread-safe state modification
thread_info->set_dead();
thread_info->add_child(child_thread);

// Thread-safe state reading
bool is_dead = thread_info->is_dead();
auto children = thread_info->get_children();
```

### 3. For Plugin Developers
```cpp
// Thread-safe foreign field access
auto accessor = thread_manager->get_field_accessor("field_name");
if (accessor) {
    auto value = accessor->get(thread_info);
}

// Thread-safe foreign table access
auto table = thread_manager->get_table("table_name");
if (table) {
    auto entry = table->get_entry("key");
}
```

## Testing Thread Safety

### 1. Concurrent Access Tests
- Multiple threads reading from thread table
- Multiple threads writing to thread table
- Mixed read-write operations
- Stress testing with high concurrency

### 2. Deadlock Prevention Tests
- Nested lock acquisition
- Lock ordering consistency
- Timeout-based deadlock detection

### 3. Performance Tests
- Throughput under concurrent access
- Lock contention measurement
- Memory usage with mutexes

## Migration Guide

### 1. Existing Code Compatibility
- All existing public APIs remain unchanged
- Thread safety is transparent to users
- No breaking changes to interface

### 2. Performance Impact
- Minimal overhead for single-threaded usage
- Slight overhead for multi-threaded usage due to mutex operations
- Benefits of thread safety outweigh performance costs

### 3. Debugging Thread Issues
- Use thread sanitizer tools
- Monitor lock contention
- Profile mutex usage patterns

## Future Enhancements

### 1. Lock-Free Data Structures
- Consider lock-free hash tables for high-concurrency scenarios
- Atomic operations for simple counters
- RCU (Read-Copy Update) for rarely-modified data

### 2. Adaptive Locking
- Dynamic lock selection based on contention
- Spin locks for short critical sections
- Hierarchical locking for complex data structures

### 3. Monitoring and Metrics
- Lock contention metrics
- Thread safety violation detection
- Performance profiling tools

## Conclusion

The thread safety implementation provides robust protection for concurrent access to thread manager and thread info data structures while maintaining good performance characteristics. The use of appropriate mutex types and lock patterns ensures thread safety without excessive overhead.

Key benefits:
- **Thread safety**: Protected concurrent access
- **Performance**: Optimized for read-heavy workloads
- **Compatibility**: No breaking changes to existing APIs
- **Maintainability**: Clear patterns and documentation
- **Scalability**: Designed for multi-threaded environments
