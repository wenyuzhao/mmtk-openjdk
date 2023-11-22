/*
 * Copyright (c) 1998, 2017, Oracle and/or its affiliates. All rights reserved.
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

#include "precompiled.hpp"
#include "mmtk.h"
#include "mmtkVMCompanionThread.hpp"
#include "runtime/mutex.hpp"
#include "logging/log.hpp"
#include "gc/shared/gcLocker.hpp"

MMTkVMCompanionThread::MMTkVMCompanionThread():
    NamedThread(),
    _desired_state(_threads_resumed),
    _reached_state(_threads_resumed) {
  set_name("MMTK VM Companion Thread");
  _lock = new Monitor(Monitor::nonleaf,
                      "MMTkVMCompanionThread::_lock",
                      true,
                      Monitor::_safepoint_check_never);
}

MMTkVMCompanionThread::~MMTkVMCompanionThread() {
  guarantee(false, "MMTkVMCompanionThread deletion must fix the race with VM termination");
}

void MMTkVMCompanionThread::run() {
  this->initialize_named_thread();

  for (;;) {
    // Wait for suspend request
    log_trace(gc)("MMTkVMCompanionThread: Waiting for suspend request...");
    if (!_wait_for_gc_locker) {
      MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
      assert(_reached_state == _threads_resumed, "Threads should be running at this moment.");
      while (_desired_state != _threads_suspended) {
        _lock->wait(true);
      }
      assert(_reached_state == _threads_resumed, "Threads should still be running at this moment.");
    }

    // Let the VM thread stop the world.
    log_trace(gc)("MMTkVMCompanionThread: Letting VMThread execute VM op...");
    if (_vm_thread_requires_gc_pause) {
      guarantee(!_wait_for_gc_locker, "VM thread is triggering a GC when the MMTkVMCompanionThread is waiting for GC locker");
      MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
      _vm_thread_requires_gc_pause = false;
      _vm_thread_suspend_for_gc = true;
      _lock->notify_all();
      while (_vm_thread_suspend_for_gc) {
        _lock->wait(Mutex::_no_safepoint_check_flag);
      }
    } else {
      if (_wait_for_gc_locker) {
        // When VM_MMTkSTWOperation early exits due to a jni critical region,
        // _wait_for_gc_locker will be set to true before exsting safepoint.
        // This main loop will continue one more iteration and reach here.
        // We wait until GC locker is inactive, to avoid busy looping.
        #ifndef PRODUCT
          auto safepoint_check_required = JNICritical_lock->_safepoint_check_required;
          JNICritical_lock->_safepoint_check_required = Monitor::_safepoint_check_sometimes;
        #endif
        MutexLockerEx locker(JNICritical_lock, Mutex::_no_safepoint_check_flag);
        while (GCLocker::is_active_and_needs_gc()) {
          #ifndef PRODUCT
            JNICritical_lock->_safepoint_check_required = Monitor::_safepoint_check_sometimes;
          #endif
          JNICritical_lock->wait(true);
        }
        #ifndef PRODUCT
          JNICritical_lock->_safepoint_check_required = safepoint_check_required;
        #endif
        // clear the flag
        _wait_for_gc_locker = false;
      }
      VM_MMTkSTWOperation op(this);
      // VMThread::execute() is blocking. The companion thread will be blocked
      // here waiting for the VM thread to execute op, and the VM thread will
      // be blocked in reach_suspended_and_wait_for_resume() until a GC thread
      // calls request(_threads_resumed).
      VMThread::execute(&op);
    }

    // Tell the waiter thread that the world has resumed.
    log_trace(gc)("MMTkVMCompanionThread: Notifying threads resumption...");
    if (!_wait_for_gc_locker) {
      MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
      assert(_desired_state == _threads_resumed, "start-the-world should be requested.");
      assert(_reached_state == _threads_suspended, "Threads should still be suspended at this moment.");
      _reached_state = _threads_resumed;
      _lock->notify_all();
    }
  }
}

// Request stop-the-world or start-the-world.  This method is supposed to be
// called by a GC thread.
//
// If wait_until_reached is true, the caller will block until all Java threads
// have stopped, or until they have been waken up.
//
// If wait_until_reached is false, the caller will return immediately, while
// the companion thread will ask the VM thread to perform the state transition
// in the background. The caller may call the wait_for_reached method to block
// until the desired state is reached.
void MMTkVMCompanionThread::request(stw_state desired_state, bool wait_until_reached) {
  assert(!Thread::current()->is_VM_thread(), "Requests can only be made by GC threads. Found VM thread.");
  assert(Thread::current() != this, "Requests can only be made by GC threads. Found companion thread.");
  assert(!Thread::current()->is_Java_thread(), "Requests can only be made by GC threads. Found Java thread.");

  MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
  assert(_desired_state != desired_state, "State %d already requested.", desired_state);
  _desired_state = desired_state;
  _lock->notify_all();

  if (wait_until_reached) {
    while (_reached_state != desired_state) {
      _lock->wait(true);
    }
  }
}

void MMTkVMCompanionThread::vm_thread_requires_gc_pause() {
  MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
  _vm_thread_requires_gc_pause = true;
}

void MMTkVMCompanionThread::block_vm_thread() {
  {
    MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
    while (!_vm_thread_suspend_for_gc) {
      _lock->wait(Mutex::_no_safepoint_check_flag);
    }
  }

  VM_MMTkSTWOperation op(this);
  VMThread::execute(&op);

  {
    MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
    _vm_thread_suspend_for_gc = false;
    _lock->notify_all();
  }
}

// Wait until the desired state is reached.  Usually called after calling the
// request method.  Supposed to be called by a GC thread.
void MMTkVMCompanionThread::wait_for_reached(stw_state desired_state) {
  assert(!Thread::current()->is_VM_thread(), "Supposed to be called by GC threads. Found VM thread.");
  assert(Thread::current() != this, "Supposed to be called by GC threads. Found companion thread.");
  assert(!Thread::current()->is_Java_thread(), "Supposed to be called by GC threads. Found Java thread.");

  MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);
  assert(_desired_state == desired_state, "State %d not requested.", desired_state);

  while (_reached_state != desired_state) {
    _lock->wait(true);
  }
}

// Called by the VM thread to indicate that all Java threads have stopped.
// This method will block until the GC requests start-the-world.
void MMTkVMCompanionThread::reach_suspended_and_wait_for_resume() {
  assert(Thread::current()->is_VM_thread(), "reach_suspended_and_wait_for_resume can only be executed by the VM thread");

  MutexLockerEx locker(_lock, Mutex::_no_safepoint_check_flag);

  // Tell the waiter thread that the world has stopped.
  _reached_state = _threads_suspended;
  _lock->notify_all();

  // Wait until resume-the-world is requested
  while (_desired_state != _threads_resumed) {
    _lock->wait(true);
  }
}
