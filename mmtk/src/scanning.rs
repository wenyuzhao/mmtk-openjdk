use super::gc_work::*;
use super::{NewBuffer, SINGLETON, UPCALLS};
use crate::OpenJDK;
use mmtk::memory_manager;
use mmtk::scheduler::ProcessEdgesWork;
use mmtk::scheduler::WorkBucketStage;
use mmtk::util::opaque_pointer::*;
use mmtk::util::{Address, ObjectReference};
use mmtk::vm::{EdgeVisitor, Scanning};
use mmtk::Mutator;
use mmtk::MutatorContext;

pub struct VMScanning {}

pub(crate) fn create_process_edges_work_vec<W: ProcessEdgesWork<VM = OpenJDK>>(buf: Vec<Address>) {
    if !buf.is_empty() {
        let w = W::new(buf, true, &SINGLETON);
        if W::RC_ROOTS {
            crate::current_worker().add_work(WorkBucketStage::RCProcessIncs, w);
        } else {
            memory_manager::add_work_packet(&SINGLETON, WorkBucketStage::Closure, w);
        }
    }
}

pub(crate) extern "C" fn create_process_edges_work<W: ProcessEdgesWork<VM = OpenJDK>>(
    ptr: *mut Address,
    length: usize,
    capacity: usize,
) -> NewBuffer {
    if !ptr.is_null() {
        let buf = unsafe { Vec::<Address>::from_raw_parts(ptr, length, capacity) };
        let w = W::new(buf, true, &SINGLETON);
        if W::RC_ROOTS {
            crate::current_worker().add_work(WorkBucketStage::RCProcessIncs, w);
        } else {
            memory_manager::add_work_packet(&SINGLETON, WorkBucketStage::Closure, w);
        }
    }
    let (ptr, _, capacity) = {
        // TODO: Use Vec::into_raw_parts() when the method is available.
        use std::mem::ManuallyDrop;
        let new_vec = Vec::with_capacity(W::CAPACITY);
        let mut me = ManuallyDrop::new(new_vec);
        (me.as_mut_ptr(), me.len(), me.capacity())
    };
    NewBuffer { ptr, capacity }
}

impl Scanning<OpenJDK> for VMScanning {
    const SCAN_MUTATORS_IN_SAFEPOINT: bool = false;
    const SINGLE_THREAD_MUTATOR_SCANNING: bool = false;

    #[inline]
    fn scan_object<EV: EdgeVisitor>(
        tls: VMWorkerThread,
        object: ObjectReference,
        edge_visitor: &mut EV,
    ) {
        crate::object_scanning::scan_object(object, edge_visitor, tls)
    }

    #[inline(always)]
    fn obj_array_data(o: ObjectReference) -> &'static [ObjectReference] {
        crate::object_scanning::obj_array_data(unsafe { std::mem::transmute(o) })
    }

    #[inline(always)]
    fn is_obj_array(o: ObjectReference) -> bool {
        crate::object_scanning::is_obj_array(unsafe { std::mem::transmute(o) })
    }

    fn notify_initial_thread_scan_complete(_partial_scan: bool, _tls: VMWorkerThread) {
        // unimplemented!()
        // TODO
    }

    fn scan_thread_roots<W: ProcessEdgesWork<VM = OpenJDK>>() {
        let process_edges = create_process_edges_work::<W>;
        unsafe {
            ((*UPCALLS).scan_thread_roots)(process_edges as _);
        }
    }

    fn scan_thread_root<W: ProcessEdgesWork<VM = OpenJDK>>(
        mutator: &'static mut Mutator<OpenJDK>,
        _tls: VMWorkerThread,
    ) {
        let tls = mutator.get_tls();
        let process_edges = create_process_edges_work::<W>;
        unsafe {
            ((*UPCALLS).scan_thread_root)(process_edges as _, tls);
        }
    }

    fn scan_vm_specific_roots<W: ProcessEdgesWork<VM = OpenJDK>>() {
        memory_manager::add_work_packets(
            &SINGLETON,
            WorkBucketStage::RCProcessIncs,
            vec![
                Box::new(ScanCodeCacheRoots::<W>::new()),
                Box::new(ScanClassLoaderDataGraphRoots::<W>::new()),
                Box::new(ScanOopStorageSetRoots::<W>::new()), // FIXME17: Several removed roots are all put to this work packet, may cause slowdown.
                // Box::new(ScanWeakProcessorRoots::<W>::new()),
            ],
        );
        if !(Self::SCAN_MUTATORS_IN_SAFEPOINT && Self::SINGLE_THREAD_MUTATOR_SCANNING) {
            memory_manager::add_work_packet(
                &SINGLETON,
                WorkBucketStage::Unconstrained,
                ScanVMThreadRoots::<W>::new(),
            );
        }
    }

    fn supports_return_barrier() -> bool {
        unimplemented!()
    }

    fn prepare_for_roots_re_scanning() {
        unsafe {
            ((*UPCALLS).prepare_for_roots_re_scanning)();
        }
    }
}
