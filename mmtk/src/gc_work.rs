use crate::scanning;
use crate::scanning::to_slots_closure;
use crate::OpenJDK;
use crate::OpenJDKSlot;
use crate::UPCALLS;
use mmtk::scheduler::*;
use mmtk::util::Address;
use mmtk::vm::RootsWorkFactory;
use mmtk::vm::*;
use mmtk::MMTK;

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
scan_roots_work!(
    ScanClassLoaderDataGraphRoots,
    scan_class_loader_data_graph_roots
);
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
        _mmtk: &'static MMTK<OpenJDK<COMPRESSED>>,
    ) {
        let mut slots = Vec::with_capacity(scanning::WORK_PACKET_CAPACITY);

        let mut nursery_slots = 0;
        let mature_slots = 0;

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
            let mut nursery = crate::NURSERY_CODE_CACHE_ROOTS.lock().unwrap();
            for (_key, roots) in nursery.drain() {
                nursery_slots += roots.len();
                add_roots(&roots);
                // mature.insert(key, roots);
            }
        }

        probe!(mmtk_openjdk, code_cache_roots, nursery_slots, mature_slots);

        if !slots.is_empty() {
            self.factory.create_process_roots_work(slots);
        }
    }
}

pub struct ScanNewWeakHandleRoots<
    const COMPRESSED: bool,
    F: RootsWorkFactory<OpenJDKSlot<COMPRESSED>>,
> {
    factory: F,
}

impl<const COMPRESSED: bool, F: RootsWorkFactory<OpenJDKSlot<COMPRESSED>>>
    ScanNewWeakHandleRoots<COMPRESSED, F>
{
    pub fn new(factory: F) -> Self {
        Self { factory }
    }
}

impl<const COMPRESSED: bool, F: RootsWorkFactory<OpenJDKSlot<COMPRESSED>>>
    GCWork<OpenJDK<COMPRESSED>> for ScanNewWeakHandleRoots<COMPRESSED, F>
{
    fn do_work(
        &mut self,
        _worker: &mut GCWorker<OpenJDK<COMPRESSED>>,
        _mmtk: &'static MMTK<OpenJDK<COMPRESSED>>,
    ) {
        let mut new_roots = crate::NURSERY_WEAK_HANDLE_ROOTS.lock().unwrap();
        for slice in new_roots.chunks(scanning::WORK_PACKET_CAPACITY) {
            let slice =
                unsafe { std::mem::transmute::<&[Address], &[OpenJDKSlot<COMPRESSED>]>(slice) };
            self.factory.create_process_roots_work(slice.to_vec());
        }
        new_roots.clear();
    }
}
