use crate::scanning;
use crate::scanning::to_slots_closure;
use crate::scanning::WORK_PACKET_CAPACITY;
use crate::NewBuffer;
use crate::OpenJDK;
use crate::OpenJDKSlot;
use crate::SlotsClosure;
use crate::UPCALLS;
use mmtk::scheduler::*;
use mmtk::util::Address;
use mmtk::vm::RootsWorkFactory;
use mmtk::vm::*;
use mmtk::MMTK;
use slot::Slot;

macro_rules! scan_roots_work {
    ($struct_name: ident, $func_name: ident) => {
        pub struct $struct_name<VM: VMBinding, F: RootsWorkFactory<VM::VMSlot>> {
            factory: F,
            _p: std::marker::PhantomData<VM>,
        }

        impl<VM: VMBinding, F: RootsWorkFactory<VM::VMSlot>> $struct_name<VM, F> {
            pub fn new(factory: F) -> Self {
                Self {
                    factory,
                    _p: std::marker::PhantomData,
                }
            }
        }

        impl<VM: VMBinding, F: RootsWorkFactory<VM::VMSlot>> GCWork<VM> for $struct_name<VM, F> {
            fn do_work(&mut self, _worker: &mut GCWorker<VM>, _mmtk: &'static MMTK<VM>) {
                unsafe {
                    ((*UPCALLS).$func_name)(to_slots_closure(&mut self.factory));
                }
            }
        }
    };
}

scan_roots_work!(ScanUniverseRoots, scan_universe_roots);
scan_roots_work!(ScanJNIHandlesRoots, scan_jni_handle_roots);
scan_roots_work!(ScanObjectSynchronizerRoots, scan_object_synchronizer_roots);
scan_roots_work!(ScanManagementRoots, scan_management_roots);
scan_roots_work!(ScanJvmtiExportRoots, scan_jvmti_export_roots);
scan_roots_work!(ScanAOTLoaderRoots, scan_aot_loader_roots);
scan_roots_work!(ScanSystemDictionaryRoots, scan_system_dictionary_roots);
scan_roots_work!(ScanStringTableRoots, scan_string_table_roots);
scan_roots_work!(ScanWeakProcessorRoots, scan_weak_processor_roots);
scan_roots_work!(ScanVMThreadRoots, scan_vm_thread_roots);

pub struct ScanCodeCacheRoots<const COMPRESSED: bool, F: RootsWorkFactory<OpenJDKSlot<COMPRESSED>>>
{
    factory: F,
}

impl<const COMPRESSED: bool, F: RootsWorkFactory<OpenJDKSlot<COMPRESSED>>>
    ScanCodeCacheRoots<COMPRESSED, F>
{
    pub fn new(factory: F) -> Self {
        Self { factory }
    }
}

impl<const COMPRESSED: bool, F: RootsWorkFactory<OpenJDKSlot<COMPRESSED>>>
    GCWork<OpenJDK<COMPRESSED>> for ScanCodeCacheRoots<COMPRESSED, F>
{
    fn do_work(
        &mut self,
        _worker: &mut GCWorker<OpenJDK<COMPRESSED>>,
        mmtk: &'static MMTK<OpenJDK<COMPRESSED>>,
    ) {
        let is_current_gc_nursery = mmtk
            .get_plan()
            .generational()
            .is_some_and(|gen| gen.is_current_gc_nursery());

        let mut slots = Vec::with_capacity(scanning::WORK_PACKET_CAPACITY);

        let mut nursery_slots = 0;
        let mut mature_slots = 0;

        let mut add_roots = |roots: &[Address]| {
            for root in roots {
                slots.push(OpenJDKSlot::<COMPRESSED>::from(*root));
                if slots.len() >= scanning::WORK_PACKET_CAPACITY {
                    self.factory
                        .create_process_roots_work(std::mem::take(&mut slots));
                }
            }
        };

        {
            let mut mature = crate::MATURE_CODE_CACHE_ROOTS.lock().unwrap();

            // Only scan mature roots in full-heap collections.
            if !is_current_gc_nursery {
                for roots in mature.values() {
                    mature_slots += roots.len();
                    add_roots(roots);
                }
            }

            {
                let mut nursery = crate::NURSERY_CODE_CACHE_ROOTS.lock().unwrap();
                for (key, roots) in nursery.drain() {
                    nursery_slots += roots.len();
                    add_roots(&roots);
                    mature.insert(key, roots);
                }
            }
        }

        probe!(mmtk_openjdk, code_cache_roots, nursery_slots, mature_slots);

        if !slots.is_empty() {
            self.factory.create_process_roots_work(slots);
        }
        // Use the following code to scan CodeCache directly, instead of scanning the "remembered set".
        // unsafe {
        //     ((*UPCALLS).scan_code_cache_roots)(to_slots_closure(&mut self.factory));
        // }
    }
}

extern "C" fn report_slots_and_renew_buffer_cld<
    S: Slot,
    F: RootsWorkFactory<S>,
    const WEAK: bool,
    const ALL_STRONG: bool,
>(
    ptr: *mut Address,
    length: usize,
    capacity: usize,
    factory_ptr: *mut libc::c_void,
) -> NewBuffer {
    if !ptr.is_null() {
        let ptr = ptr as *mut S;
        let buf = unsafe { Vec::<S>::from_raw_parts(ptr, length, capacity) };
        let factory: &mut F = unsafe { &mut *(factory_ptr as *mut F) };
        factory.create_process_roots_work(buf);
    }
    let (ptr, _, capacity) = {
        // TODO: Use Vec::into_raw_parts() when the method is available.
        use std::mem::ManuallyDrop;
        let new_vec = Vec::with_capacity(WORK_PACKET_CAPACITY);
        let mut me = ManuallyDrop::new(new_vec);
        (me.as_mut_ptr(), me.len(), me.capacity())
    };
    NewBuffer { ptr, capacity }
}

fn to_slots_closure_cld<
    S: Slot,
    F: RootsWorkFactory<S>,
    const WEAK: bool,
    const ALL_STRONG: bool,
>(
    factory: &mut F,
) -> SlotsClosure {
    SlotsClosure {
        func: report_slots_and_renew_buffer_cld::<S, F, WEAK, ALL_STRONG>,
        data: factory as *mut F as *mut libc::c_void,
    }
}

pub struct ScanClassLoaderDataGraphRoots<VM: VMBinding, F: RootsWorkFactory<VM::VMSlot>> {
    factory: F,
    _p: std::marker::PhantomData<VM>,
}

impl<VM: VMBinding, F: RootsWorkFactory<VM::VMSlot>> ScanClassLoaderDataGraphRoots<VM, F> {
    pub fn new(factory: F) -> Self {
        Self {
            factory,
            _p: std::marker::PhantomData,
        }
    }
}

impl<VM: VMBinding, F: RootsWorkFactory<VM::VMSlot>> GCWork<VM>
    for ScanClassLoaderDataGraphRoots<VM, F>
{
    fn do_work(&mut self, _worker: &mut GCWorker<VM>, _mmtk: &'static MMTK<VM>) {
        unsafe {
            ((*UPCALLS).scan_class_loader_data_graph_roots)(
                to_slots_closure_cld::<VM::VMSlot, F, false, true>(&mut self.factory),
                to_slots_closure_cld::<VM::VMSlot, F, true, false>(&mut self.factory),
                true,
            );
        }
    }
}
