/*
 * Copyright (c) 2001, 2017, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#ifndef MMTK_OPENJDK_MMTK_HEAP_HPP
#define MMTK_OPENJDK_MMTK_HEAP_HPP

#include "mmtkBarrierSet.hpp"
#include "gc/shared/collectedHeap.hpp"
#include "gc/shared/collectorPolicy.hpp"
#include "gc/shared/gcPolicyCounters.hpp"
#include "gc/shared/gcWhen.hpp"
#include "gc/shared/oopStorage.hpp"
#include "gc/shared/oopStorageParState.hpp"
#include "gc/shared/strongRootsScope.hpp"
#include "gc/shared/workgroup.hpp"
#include "gc/shared/softRefPolicy.hpp"
#include "memory/iterator.hpp"
#include "memory/metaspace.hpp"
#include "mmtkCollectorPolicy.hpp"
#include "mmtkFinalizerThread.hpp"
#include "mmtkMemoryPool.hpp"
#include "utilities/growableArray.hpp"
#include "utilities/ostream.hpp"

#define WORKER_STACK_SIZE (64 * 1024 * 1024)

class GCMemoryManager;
class MemoryPool;
//class mmtkGCTaskManager;
class MMTkVMCompanionThread;
class MMTkHeap : public CollectedHeap {
  MMTkCollectorPolicy* _collector_policy;
  SoftRefPolicy _soft_ref_policy;
  MMTkMemoryPool* _mmtk_pool;
  GCMemoryManager* _mmtk_manager;
  HeapWord* _start;
  HeapWord* _end;
  static MMTkHeap* _heap;
  size_t _n_workers;
  Monitor* _gc_lock;
  ContiguousSpace* _space;
  int _num_root_scan_tasks;
  MMTkVMCompanionThread* _companion_thread;
  WorkGang* _workers;
public:
  AllocatorSelector default_allocator_selector;

  MMTkHeap(MMTkCollectorPolicy* policy);

  WorkGang* workers() const { return _workers; }

  void schedule_finalizer();

  void set_is_gc_active(bool is_gc_active) {
    _is_gc_active = is_gc_active;
  }

  inline static MMTkHeap* heap() {
    return _heap;
  }

  static HeapWord* allocate_from_tlab(Klass* klass, Thread* thread, size_t size);

  virtual jint initialize() override;
  virtual void enable_collection() override;

  virtual HeapWord* mem_allocate(size_t size, bool* gc_overhead_limit_was_exceeded) override;
  HeapWord* mem_allocate_nonmove(size_t size, bool* gc_overhead_limit_was_exceeded);

  MMTkVMCompanionThread* companion_thread() const {
    return _companion_thread;
  }


  virtual Name kind() const override {
    return CollectedHeap::ThirdPartyHeap;
  }
  virtual const char* name() const override {
    return "MMTk";
  }
  static const char* version();

  virtual size_t capacity() const override;
  virtual size_t used() const override;

  virtual bool is_maximal_no_gc() const override;

  virtual size_t max_capacity() const override;
  virtual bool is_in(const void* p) const override;
  virtual bool is_in_reserved(const void* p) const override;
  virtual bool supports_tlab_allocation() const override;

  virtual bool supports_inline_contig_alloc() const override {
    return MMTK_ENABLE_ALLOCATION_FASTPATH && !disable_fast_alloc();
  }

  // The amount of space available for thread-local allocation buffers.
  virtual size_t tlab_capacity(Thread *thr) const override;

  // The amount of used space for thread-local allocation buffers for the given thread.
  virtual size_t tlab_used(Thread *thr) const override;

  void new_collector_thread() {
    _n_workers += 1;
  }

  Monitor* gc_lock() {
    return _gc_lock;
  }

  bool can_elide_tlab_store_barriers() const;


  bool can_elide_initializing_store_barrier(oop new_obj);

  // mark to be thus strictly sequenced after the stores.
  bool card_mark_must_follow_store() const;

  virtual void collect(GCCause::Cause cause) override;

  // Perform a full collection
  virtual void do_full_collection(bool clear_all_soft_refs) override;

  virtual void collect_as_vm_thread(GCCause::Cause cause) override;


  // Return the CollectorPolicy for the heap
  virtual CollectorPolicy* collector_policy() const override;

  virtual SoftRefPolicy* soft_ref_policy() override;

  virtual GrowableArray<GCMemoryManager*> memory_managers() override;
  virtual GrowableArray<MemoryPool*> memory_pools() override;

  // Iterate over all objects, calling "cl.do_object" on each.
  virtual void object_iterate(ObjectClosure* cl) override;

  // Similar to object_iterate() except iterates only
  // over live objects.
  virtual void safe_object_iterate(ObjectClosure* cl) override;

  virtual HeapWord* block_start(const void* addr) const override;

  virtual size_t block_size(const HeapWord* addr) const override;

  virtual bool block_is_obj(const HeapWord* addr) const override;

  virtual jlong millis_since_last_gc() override;

  virtual void prepare_for_verify() override;


private:

  virtual void initialize_serviceability() override;

public:

  // Print heap information on the given outputStream.
  virtual void print_on(outputStream* st) const override;


  // Print all GC threads (other than the VM thread)
  // used by this heap.
  virtual void print_gc_threads_on(outputStream* st) const override;

  // Iterator for all GC threads (other than VM thread)
  virtual void gc_threads_do(ThreadClosure* tc) const override;

  // Print any relevant tracing info that flags imply.
  // Default implementation does nothing.
  virtual void print_tracing_info() const override;


  // An object is scavengable if its location may move during a scavenge.
  // (A scavenge is a GC which is not a full GC.)
  virtual inline bool is_scavengable(oop obj) override { return true; }
  // Registering and unregistering an nmethod (compiled code) with the heap.
  // Override with specific mechanism for each specialized heap type.
  virtual void register_nmethod(nmethod* nm) override;
  virtual void unregister_nmethod(nmethod* nm) override;

  // Heap verification
  virtual void verify(VerifyOption option) override;

  virtual void post_initialize() override;

  void scan_roots(OopClosure& cl);

  void scan_thread_roots(OopClosure& cl);

  void scan_universe_roots(OopClosure& cl);
  void scan_jni_handle_roots(OopClosure& cl);
  void scan_object_synchronizer_roots(OopClosure& cl);
  void scan_management_roots(OopClosure& cl);
  void scan_jvmti_export_roots(OopClosure& cl);
  void scan_aot_loader_roots(OopClosure& cl);
  void scan_system_dictionary_roots(OopClosure& cl);
  void scan_code_cache_roots(OopClosure& cl);
  void scan_string_table_roots(OopClosure& cl, OopStorage::ParState<false, false>* par_state_string);
  void scan_class_loader_data_graph_roots(OopClosure& cl, OopClosure& weak_cl, bool scan_all_strong_roots);
  void scan_weak_processor_roots(OopClosure& cl);
  void scan_vm_thread_roots(OopClosure& cl);

  void complete_cleaning(BoolObjectClosure* is_alive, OopClosure* forward, bool class_unloading_occurred);

  jlong _last_gc_time;
};


#endif // MMTK_OPENJDK_MMTK_HEAP_HPP
