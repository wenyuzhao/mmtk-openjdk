extern crate libc;
extern crate mmtk;
#[macro_use]
extern crate lazy_static;
extern crate once_cell;

use std::collections::HashMap;
use std::ptr::null_mut;
use std::sync::atomic::AtomicUsize;
use std::sync::Mutex;

use libc::{c_char, c_void, uintptr_t};
use mmtk::util::alloc::AllocationError;
use mmtk::util::heap::layout::vm_layout_constants::VM_LAYOUT_CONSTANTS;
use mmtk::util::opaque_pointer::*;
use mmtk::util::{Address, ObjectReference};
use mmtk::vm::edge_shape::Edge;
use mmtk::vm::VMBinding;
use mmtk::MMTKBuilder;
use mmtk::Mutator;
use mmtk::MMTK;

mod abi;
pub mod active_plan;
pub mod api;
mod build_info;
pub mod collection;
mod gc_work;
pub mod object_model;
mod object_scanning;
pub mod reference_glue;
pub mod scanning;
pub(crate) mod vm_metadata;

#[repr(C)]
pub struct NewBuffer {
    pub ptr: *mut Address,
    pub capacity: usize,
}

/// A closure for reporting mutators.  The C++ code should pass `data` back as the last argument.
#[repr(C)]
pub struct MutatorClosure {
    pub func: *const extern "C" fn(mutator: *mut Mutator<OpenJDK>, data: *mut libc::c_void),
    pub data: *mut libc::c_void,
}

/// A closure for reporting root edges.  The C++ code should pass `data` back as the last argument.
#[repr(C)]
pub struct EdgesClosure {
    pub func:
        *const extern "C" fn(buf: *mut Address, size: usize, cap: usize, data: *const libc::c_void),
    pub data: *const libc::c_void,
}

#[repr(C)]
pub struct OpenJDK_Upcalls {
    pub stop_all_mutators: extern "C" fn(
        tls: VMWorkerThread,
        scan_mutators_in_safepoint: bool,
        closure: MutatorClosure,
    ),
    pub resume_mutators: extern "C" fn(tls: VMWorkerThread),
    pub spawn_gc_thread: extern "C" fn(tls: VMThread, kind: libc::c_int, ctx: *mut libc::c_void),
    pub block_for_gc: extern "C" fn(),
    pub out_of_memory: extern "C" fn(tls: VMThread, err_kind: AllocationError),
    pub get_next_mutator: extern "C" fn() -> *mut Mutator<OpenJDK>,
    pub reset_mutator_iterator: extern "C" fn(),
    pub scan_object: extern "C" fn(trace: *mut c_void, object: ObjectReference, tls: OpaquePointer),
    pub dump_object: extern "C" fn(object: ObjectReference),
    pub get_object_size: extern "C" fn(object: ObjectReference) -> usize,
    pub get_mmtk_mutator: extern "C" fn(tls: VMMutatorThread) -> *mut Mutator<OpenJDK>,
    pub is_mutator: extern "C" fn(tls: VMThread) -> bool,
    pub harness_begin: extern "C" fn(),
    pub harness_end: extern "C" fn(),
    pub compute_klass_mem_layout_checksum: extern "C" fn() -> usize,
    pub offset_of_static_fields: extern "C" fn() -> i32,
    pub static_oop_field_count_offset: extern "C" fn() -> i32,
    pub referent_offset: extern "C" fn() -> i32,
    pub discovered_offset: extern "C" fn() -> i32,
    pub dump_object_string: extern "C" fn(object: ObjectReference) -> *const c_char,
    pub scan_all_thread_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_thread_roots: extern "C" fn(closure: EdgesClosure, tls: VMMutatorThread),
    pub scan_universe_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_jni_handle_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_object_synchronizer_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_management_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_jvmti_export_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_aot_loader_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_system_dictionary_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_code_cache_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_string_table_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_class_loader_data_graph_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_weak_processor_roots: extern "C" fn(closure: EdgesClosure),
    pub scan_vm_thread_roots: extern "C" fn(closure: EdgesClosure),
    pub number_of_mutators: extern "C" fn() -> usize,
    pub schedule_finalizer: extern "C" fn(),
    pub prepare_for_roots_re_scanning: extern "C" fn(),
    pub enqueue_references: extern "C" fn(objects: *const ObjectReference, len: usize),
    pub compressed_klass_base: extern "C" fn() -> Address,
    pub compressed_klass_shift: extern "C" fn() -> usize,
    pub nmethod_fix_relocation: extern "C" fn(Address),
}

pub static mut UPCALLS: *const OpenJDK_Upcalls = null_mut();

#[no_mangle]
pub static GLOBAL_SIDE_METADATA_BASE_ADDRESS: uintptr_t =
    crate::mmtk::util::metadata::side_metadata::GLOBAL_SIDE_METADATA_BASE_ADDRESS.as_usize();

#[no_mangle]
pub static GLOBAL_SIDE_METADATA_VM_BASE_ADDRESS: uintptr_t =
    crate::mmtk::util::metadata::side_metadata::GLOBAL_SIDE_METADATA_VM_BASE_ADDRESS.as_usize();

#[no_mangle]
pub static GLOBAL_ALLOC_BIT_ADDRESS: uintptr_t =
    crate::mmtk::util::metadata::side_metadata::ALLOC_SIDE_METADATA_ADDR.as_usize();

static mut LOG_BYTES_IN_OOP: usize = 3;

#[inline(always)]
fn log_bytes_in_oop() -> usize {
    unsafe { LOG_BYTES_IN_OOP }
}

lazy_static! {
    static ref USE_COMPRESSED_OOPS: bool = {
        let enable = std::env::var("MMTK_COMPRESSED_PTRS")
            .map(|s| s.trim() != "0" || s.trim() != "false")
            .unwrap_or(false);
        if enable {
            unsafe { LOG_BYTES_IN_OOP = 2 }
        }
        enable
    };
}

#[derive(Default)]
pub struct OpenJDK;

/// The type of edges in OpenJDK.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct OpenJDKEdge(pub Address);

impl OpenJDKEdge {
    const MASK: usize = 1usize << 63;

    const fn is_compressed(&self) -> bool {
        self.0.as_usize() & Self::MASK != 0
    }

    const fn untagged_address(&self) -> Address {
        unsafe { Address::from_usize(self.0.as_usize() << 1 >> 1) }
    }

    pub const fn as_compressed(&self) -> Self {
        unsafe { Self(Address::from_usize(self.0.as_usize() | Self::MASK)) }
    }
}

impl Edge for OpenJDKEdge {
    /// Load object reference from the edge.
    fn load(&self) -> ObjectReference {
        let slot = self.untagged_address();
        if self.is_compressed() {
            let v = unsafe { slot.load::<u32>() as usize };
            if v == 0 {
                ObjectReference::NULL
            } else {
                unsafe { (VM_LAYOUT_CONSTANTS.heap_start - 4096 + (v << 3)).to_object_reference() }
            }
        } else {
            unsafe { slot.load::<ObjectReference>() }
        }
    }

    /// Store the object reference `object` into the edge.
    fn store(&self, object: ObjectReference) {
        let slot = self.untagged_address();
        if self.is_compressed() {
            if object.is_null() {
                unsafe { slot.store(0u32) };
            } else {
                unsafe {
                    slot.store(
                        ((object.to_address() - VM_LAYOUT_CONSTANTS.heap_start + 4096) >> 3) as u32,
                    )
                }
            }
        } else {
            unsafe { slot.store(object) }
        }
    }
}

impl VMBinding for OpenJDK {
    type VMObjectModel = object_model::VMObjectModel;
    type VMScanning = scanning::VMScanning;
    type VMCollection = collection::VMCollection;
    type VMActivePlan = active_plan::VMActivePlan;
    type VMReferenceGlue = reference_glue::VMReferenceGlue;

    type VMEdge = OpenJDKEdge;
}

use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

pub static MMTK_INITIALIZED: AtomicBool = AtomicBool::new(false);

lazy_static! {
    pub static ref BUILDER: Mutex<MMTKBuilder> = Mutex::new(MMTKBuilder::new());
    pub static ref SINGLETON: MMTK<OpenJDK> = {
        let mut builder = BUILDER.lock().unwrap();
        if *USE_COMPRESSED_OOPS {
            builder.set_option("use_35bit_address_space", "true");
        }
        assert!(!MMTK_INITIALIZED.load(Ordering::Relaxed));
        let ret = mmtk::memory_manager::mmtk_init(&builder);
        MMTK_INITIALIZED.store(true, std::sync::atomic::Ordering::SeqCst);
        *ret
    };
}

#[no_mangle]
pub static MMTK_MARK_COMPACT_HEADER_RESERVED_IN_BYTES: usize =
    mmtk::util::alloc::MarkCompactAllocator::<OpenJDK>::HEADER_RESERVED_IN_BYTES;

lazy_static! {
    /// A global storage for all the cached CodeCache root pointers
    static ref CODE_CACHE_ROOTS: Mutex<HashMap<Address, Vec<Address>>> = Mutex::new(HashMap::new());
}

/// A counter tracking the total size of the `CODE_CACHE_ROOTS`.
static CODE_CACHE_ROOTS_SIZE: AtomicUsize = AtomicUsize::new(0);
