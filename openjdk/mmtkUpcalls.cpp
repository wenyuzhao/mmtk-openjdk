/*
 * Copyright (c) 2017, Red Hat, Inc. and/or its affiliates.
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
 * Please contact Sun 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */

#include "precompiled.hpp"
#include "classfile/stringTable.hpp"
#include "code/nmethod.hpp"
#include "memory/iterator.hpp"
#include "memory/iterator.inline.hpp"
#include "memory/resourceArea.hpp"
#include "mmtkCollectorThread.hpp"
#include "mmtkContextThread.hpp"
#include "mmtkHeap.hpp"
#include "mmtkRootsClosure.hpp"
#include "mmtkUpcalls.hpp"
#include "mmtkVMCompanionThread.hpp"
#include "runtime/mutexLocker.hpp"
#include "runtime/os.hpp"
#include "runtime/safepoint.hpp"
#include "runtime/thread.hpp"
#include "runtime/threadSMR.hpp"
#include "runtime/vmThread.hpp"
#include "utilities/debug.hpp"
#include "gc/shared/weakProcessor.hpp"

static size_t mmtk_start_the_world_count = 0;

static void mmtk_stop_all_mutators(void *tls, void (*create_stack_scan_work)(void* mutator)) {
  MMTkHeap::_create_stack_scan_work = create_stack_scan_work;

  ClassLoaderDataGraph::clear_claimed_marks();
  CodeCache::gc_prologue();

  BiasedLocking::preserve_marks();
#if COMPILER2_OR_JVMCI
  DerivedPointerTable::clear();
#endif

  log_debug(gc)("Requesting the VM to suspend all mutators...");
  MMTkHeap::heap()->companion_thread()->request(MMTkVMCompanionThread::_threads_suspended, true);
  log_debug(gc)("Mutators stopped. Now enumerate threads for scanning...");

  {
    JavaThreadIteratorWithHandle jtiwh;
    while (JavaThread *cur = jtiwh.next()) {
      MMTkHeap::heap()->report_java_thread_yield(cur);
    }
  }
  log_debug(gc)("Finished enumerating threads.");
}

class MMTkIsAliveClosure : public BoolObjectClosure {
public:
  virtual bool do_object_b(oop p) {
    return mmtk_is_live((void*) p) != 0;
  }
};

class MMTkForwardClosure : public OopIterateClosure {
 public:
  MMTkForwardClosure() : OopIterateClosure(NULL) {}

  virtual void do_oop(oop* o) {
    *o = (oop) mmtk_get_forwarded_ref((void*) *o);
  }

  virtual void do_oop(narrowOop* o) {}
  virtual ReferenceIterationMode reference_iteration_mode() { return DO_FIELDS; }
  debug_only(virtual bool should_verify_oops() { return false; })

  virtual bool do_metadata() { return false; }
  virtual void do_klass(Klass* k) { ShouldNotReachHere(); }
  virtual void do_cld(ClassLoaderData* cld) { ShouldNotReachHere(); }

};

/// Clean up the weak-ref storage and update pointers.
static void mmtk_process_weak_ref() {
  MMTkIsAliveClosure is_alive;
  MMTkForwardClosure forward;

  WeakProcessor::weak_oops_do(&is_alive, &forward);

  bool purged_class = SystemDictionary::do_unloading(NULL);

  CodeBlobToOopClosure adjust_from_blobs(&forward, CodeBlobToOopClosure::FixRelocations);
  CodeCache::blobs_do(&adjust_from_blobs);
  CodeCache::do_unloading(&is_alive, purged_class);
  Klass::clean_weak_klass_links(purged_class);

  StringTable::oops_do(&forward);
  StringTable::unlink(&is_alive);

  SymbolTable::unlink();

  // TODO: This does not take effect for now. But we need this later to support class unloading
  ClassLoaderDataGraph::clear_claimed_marks();
  CLDToOopClosure adjust_cld_closure(&forward);
  ClassLoaderDataGraph::cld_do(&adjust_cld_closure);
  ClassLoaderDataGraph::oops_do(&forward, true);
}

static void mmtk_resume_mutators(void *tls) {
  ClassLoaderDataGraph::purge();
  BiasedLocking::restore_marks();
  CodeCache::gc_epilogue();
  JvmtiExport::gc_epilogue();
#if COMPILER2_OR_JVMCI
  DerivedPointerTable::update_pointers();
#endif

  MMTkHeap::_create_stack_scan_work = NULL;

  log_debug(gc)("Requesting the VM to resume all mutators...");
  MMTkHeap::heap()->companion_thread()->request(MMTkVMCompanionThread::_threads_resumed, true);
  log_debug(gc)("Mutators resumed. Now notify any mutators waiting for GC to finish...");

  {
    MutexLockerEx locker(MMTkHeap::heap()->gc_lock(), true);
    mmtk_start_the_world_count++;
    MMTkHeap::heap()->gc_lock()->notify_all();
  }
  log_debug(gc)("Mutators notified.");
}

static const int GC_THREAD_KIND_CONTROLLER = 0;
static const int GC_THREAD_KIND_WORKER = 1;
static void mmtk_spawn_collector_thread(void* tls, int kind, void* ctx) {
  switch (kind) {
    case GC_THREAD_KIND_CONTROLLER: {
      MMTkContextThread* t = new MMTkContextThread(ctx);
      if (!os::create_thread(t, os::pgc_thread)) {
        printf("Failed to create thread");
        guarantee(false, "panic");
      }
      os::start_thread(t);
      break;
    }
    case GC_THREAD_KIND_WORKER: {
      MMTkHeap::heap()->new_collector_thread();
      MMTkCollectorThread* t = new MMTkCollectorThread(ctx);
      if (!os::create_thread(t, os::pgc_thread)) {
        printf("Failed to create thread");
        guarantee(false, "panic");
      }
      os::start_thread(t);
      break;
    }
    default: {
      printf("Unexpected thread kind: %d\n", kind);
      guarantee(false, "panic");
    }
  }
}

static void mmtk_block_for_gc() {
  MMTkHeap::heap()->_last_gc_time = os::javaTimeNanos() / NANOSECS_PER_MILLISEC;
  log_debug(gc)("Thread (id=%d) will block waiting for GC to finish.", Thread::current()->osthread()->thread_id());
  {
    MutexLocker locker(MMTkHeap::heap()->gc_lock());
    size_t my_count = mmtk_start_the_world_count;
    size_t next_count = my_count + 1;

    while (mmtk_start_the_world_count < next_count) {
      MMTkHeap::heap()->gc_lock()->wait();
    }
  }
  log_debug(gc)("Thread (id=%d) resumed after GC finished.", Thread::current()->osthread()->thread_id());
}

static void mmtk_out_of_memory(void* tls, MMTkAllocationError err_kind) {
  switch (err_kind) {
  case HeapOutOfMemory :
    // Note that we have to do nothing for the case that the Java heap is too small. Since mmtk-core already
    // returns a nullptr back to the JVM, it automatically triggers an OOM exception since the JVM checks for
    // OOM every (slowpath) allocation [1]. In fact, if we report and throw an OOM exception here, the VM will
    // complain since a pending exception bit was already set when it was trying to check for OOM [2]. Hence,
    // it is best to let the JVM take care of reporting OOM itself.
    //
    // [1]: https://github.com/mmtk/openjdk/blob/e4dbe9909fa5c21685a20a1bc541fcc3b050dac4/src/hotspot/share/gc/shared/memAllocator.cpp#L83
    // [2]: https://github.com/mmtk/openjdk/blob/e4dbe9909fa5c21685a20a1bc541fcc3b050dac4/src/hotspot/share/gc/shared/memAllocator.cpp#L117
    break;
  case MmapOutOfMemory :
    // Abort the VM immediately due to insufficient system resources.
    vm_exit_out_of_memory(0, OOM_MMAP_ERROR, "MMTk: Unable to acquire more memory from the OS. Out of system resources.");
    break;
  }
}

static void* mmtk_get_mmtk_mutator(void* tls) {
  return (void*) &((Thread*) tls)->third_party_heap_mutator;
}

static bool mmtk_is_mutator(void* tls) {
  if (tls == NULL) return false;
  return ((Thread*) tls)->third_party_heap_collector == NULL;
}

template <class T>
struct MaybeUninit {
  MaybeUninit() {}
  T* operator->() {
    return (T*) &_data;
  }
  T& operator*() {
    return *((T*) &_data);
  }
private:
  char _data[sizeof(T)];
};

static MaybeUninit<JavaThreadIteratorWithHandle> jtiwh;
static bool mutator_iteration_start = true;

static void* mmtk_get_next_mutator() {
  if (mutator_iteration_start) {
    *jtiwh = JavaThreadIteratorWithHandle();
    mutator_iteration_start = false;
  }
  JavaThread *thr = jtiwh->next();
  if (thr == NULL) {
    mutator_iteration_start = true;
    return NULL;
  }
  return (void*) &thr->third_party_heap_mutator;
}

static void mmtk_reset_mutator_iterator() {
  mutator_iteration_start = true;
}


static void mmtk_compute_global_roots(void* trace, void* tls) {
  MMTkRootsClosure cl(trace);
  MMTkHeap::heap()->scan_global_roots(cl);
}

static void mmtk_compute_static_roots(void* trace, void* tls) {
  MMTkRootsClosure cl(trace);
  MMTkHeap::heap()->scan_static_roots(cl);
}

static void mmtk_compute_thread_roots(void* trace, void* tls) {
  MMTkRootsClosure cl(trace);
  MMTkHeap::heap()->scan_thread_roots(cl);
}

static void mmtk_scan_thread_roots(ProcessEdgesFn process_edges) {
  MMTkRootsClosure2 cl(process_edges);
  MMTkHeap::heap()->scan_thread_roots(cl);
}

static void mmtk_scan_thread_root(ProcessEdgesFn process_edges, void* tls) {
  ResourceMark rm;
  JavaThread* thread = (JavaThread*) tls;
  MMTkRootsClosure2 cl(process_edges);
  thread->oops_do(&cl, NULL);
}

static void mmtk_scan_object(void* trace, void* object, void* tls) {
  MMTkScanObjectClosure cl(trace);
  ((oop) object)->oop_iterate(&cl);
}

static void mmtk_dump_object(void* object) {
  oop o = (oop) object;

  // o->print();
  o->print_value();
  printf("\n");

  // o->print_address();
}

static size_t mmtk_get_object_size(void* object) {
  oop o = (oop) object;
  // Slow-dispatch only. The fast-path code is moved to rust.
  auto klass = o->klass();
  return klass->oop_size(o) << LogHeapWordSize;
}

static int mmtk_enter_vm() {
  assert(Thread::current()->is_Java_thread(), "Only Java thread can enter vm");

  JavaThread* current = ((JavaThread*) Thread::current());
  JavaThreadState state = current->thread_state();
  current->set_thread_state(_thread_in_vm);
  return (int)state;
}

static void mmtk_leave_vm(int st) {
  assert(Thread::current()->is_Java_thread(), "Only Java thread can leave vm");

  JavaThread* current = ((JavaThread*) Thread::current());
  assert(current->thread_state() == _thread_in_vm, "Cannot leave vm when the current thread is not in _thread_in_vm");
  current->set_thread_state((JavaThreadState)st);
}

static int offset_of_static_fields() {
  return InstanceMirrorKlass::offset_of_static_fields();
}

static int static_oop_field_count_offset() {
  return java_lang_Class::static_oop_field_count_offset();
}

static size_t compute_klass_mem_layout_checksum() {
  return sizeof(Klass)
    ^ sizeof(InstanceKlass)
    ^ sizeof(InstanceRefKlass)
    ^ sizeof(InstanceMirrorKlass)
    ^ sizeof(InstanceClassLoaderKlass)
    ^ sizeof(TypeArrayKlass)
    ^ sizeof(ObjArrayKlass);
}

static int referent_offset() {
  return java_lang_ref_Reference::referent_offset;
}

static int discovered_offset() {
  return java_lang_ref_Reference::discovered_offset;
}

static char* dump_object_string(void* object) {
  ResourceMark rm;
  oop o = (oop) object;
  return o->print_value_string();
}

static void mmtk_schedule_finalizer() {
  MMTkHeap::heap()->schedule_finalizer();
}

static void mmtk_scan_universe_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_universe_roots(cl); }
static void mmtk_scan_jni_handle_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_jni_handle_roots(cl); }
static void mmtk_scan_object_synchronizer_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_object_synchronizer_roots(cl); }
static void mmtk_scan_management_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_management_roots(cl); }
static void mmtk_scan_jvmti_export_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_jvmti_export_roots(cl); }
static void mmtk_scan_aot_loader_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_aot_loader_roots(cl); }
static void mmtk_scan_system_dictionary_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_system_dictionary_roots(cl); }
static void mmtk_scan_code_cache_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_code_cache_roots(cl); }
static void mmtk_scan_string_table_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_string_table_roots(cl); }
static void mmtk_scan_class_loader_data_graph_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_class_loader_data_graph_roots(cl); }
static void mmtk_scan_weak_processor_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_weak_processor_roots(cl); }
static void mmtk_scan_vm_thread_roots(ProcessEdgesFn process_edges) { MMTkRootsClosure2 cl(process_edges); MMTkHeap::heap()->scan_vm_thread_roots(cl); }

static size_t mmtk_number_of_mutators() {
  return Threads::number_of_threads();
}

static void mmtk_prepare_for_roots_re_scanning() {
#if COMPILER2_OR_JVMCI
  DerivedPointerTable::update_pointers();
  DerivedPointerTable::clear();
#endif
}

static const char* get_oop_class_name(void* object, void (*cb)(const char* ptr)) {
  ResourceMark rm;
  oop o = (oop) object;
// printf("get_oop_class_name object=%p\n", object);
  // o->print_value();
  // printf("\n");
  auto ptr = o->klass()->signature_name();
  // printf("get_oop_class_name ptr=%p\n", ptr);
  // printf("get_oop_class_name c=%d\n", *ptr);
  cb(ptr);
  return ptr;
}

static void mmtk_scan_cld(void* _obj, ProcessEdgeFn process_edge) {
  oop obj = (oop) _obj;
  const auto class_id = obj->klass()->id();
  class _OopClosure : public BasicOopIterateClosure {
    ProcessEdgeFn process_edge;
    CLDToOopClosure follow_cld_closure;
  public:
    _OopClosure(ProcessEdgeFn process_edge): process_edge(process_edge), follow_cld_closure(this) {}
    virtual void do_oop(oop* o) {
      process_edge((void*) o);
    }
    virtual void do_oop(narrowOop* o) {
      ShouldNotReachHere();
    }

    virtual bool do_metadata() {
      return true;
    }

    virtual void do_klass(Klass* k) {}

    virtual void do_cld(ClassLoaderData* cld) {
      follow_cld_closure.do_cld(cld);
    }
  };
  _OopClosure closure(process_edge);
  if (class_id == InstanceMirrorKlassID) {
    Klass* klass = java_lang_Class::as_Klass(obj);
    // We'll get NULL for primitive mirrors.
    if (klass != NULL) {
      if (klass->is_instance_klass() && InstanceKlass::cast(klass)->is_anonymous()) {
        // An anonymous class doesn't have its own class loader, so when handling
        // the java mirror for an anonymous class we need to make sure its class
        // loader data is claimed, this is done by calling do_cld explicitly.
        // For non-anonymous classes the call to do_cld is made when the class
        // loader itself is handled.

        Devirtualizer::do_cld(&closure, klass->class_loader_data());
      } else {
        // Devirtualizer::do_klass(closure, klass);
      }
    }
  } else if (class_id == InstanceClassLoaderKlassID) {
    ClassLoaderData* cld = java_lang_ClassLoader::loader_data(obj);
    // cld can be null if we have a non-registered class loader.
    if (cld != NULL) {
      Devirtualizer::do_cld(&closure, cld);
    }
  } else {
    ShouldNotReachHere();
  }
}

OpenJDK_Upcalls mmtk_upcalls = {
  mmtk_stop_all_mutators,
  mmtk_resume_mutators,
  mmtk_spawn_collector_thread,
  mmtk_block_for_gc,
  mmtk_out_of_memory,
  mmtk_get_next_mutator,
  mmtk_reset_mutator_iterator,
  mmtk_compute_static_roots,
  mmtk_compute_global_roots,
  mmtk_compute_thread_roots,
  mmtk_scan_object,
  mmtk_dump_object,
  mmtk_get_object_size,
  mmtk_get_mmtk_mutator,
  mmtk_is_mutator,
  mmtk_enter_vm,
  mmtk_leave_vm,
  compute_klass_mem_layout_checksum,
  offset_of_static_fields,
  static_oop_field_count_offset,
  referent_offset,
  discovered_offset,
  dump_object_string,
  mmtk_scan_thread_roots,
  mmtk_scan_thread_root,
  mmtk_scan_universe_roots,
  mmtk_scan_jni_handle_roots,
  mmtk_scan_object_synchronizer_roots,
  mmtk_scan_management_roots,
  mmtk_scan_jvmti_export_roots,
  mmtk_scan_aot_loader_roots,
  mmtk_scan_system_dictionary_roots,
  mmtk_scan_code_cache_roots,
  mmtk_scan_string_table_roots,
  mmtk_scan_class_loader_data_graph_roots,
  mmtk_scan_weak_processor_roots,
  mmtk_scan_vm_thread_roots,
  mmtk_number_of_mutators,
  mmtk_schedule_finalizer,
  mmtk_prepare_for_roots_re_scanning,
  get_oop_class_name,
  mmtk_process_weak_ref,
  mmtk_scan_cld,
};
