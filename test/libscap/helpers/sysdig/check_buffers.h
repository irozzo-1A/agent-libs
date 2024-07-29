#pragma once

#include <libscap/scap.h>

void check_live_same_thread_event_order(scap_t* h);

// This is a duplicate of `check_event_order` in the engines.h file. We want to avoid conflicts with
// the fork.
void check_pre_fetched_event_order(scap_t* h);

void check_refill(scap_t* h);
