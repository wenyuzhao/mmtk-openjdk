use crate::scanning::to_slots_closure;
use crate::Address;
use crate::NewBuffer;
use crate::Slot;
use crate::SlotsClosure;
use crate::UPCALLS;
use mmtk::scheduler::*;
use mmtk::vm::RootsWorkFactory;
use mmtk::vm::*;
use mmtk::MMTK;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};

thread_local! {
    pub static COUNT: AtomicUsize = AtomicUsize::new(0);
}

pub fn record_roots(len: usize) {
    super::gc_work::COUNT.with(|x| {
        let c = x.load(Ordering::Relaxed);
        x.store(c + len, Ordering::Relaxed);
    });
}

fn report_roots(name: &str, ms: f32) {
    super::gc_work::COUNT.with(|x| {
        let c = x.load(Ordering::Relaxed);
        eprintln!(" - {} roots count: {} ({:.3}ms)", name, c, ms);
        x.store(0, Ordering::Relaxed);
    });
}

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
                let t = if cfg!(feature = "roots_breakdown") {
                    Some(std::time::SystemTime::now())
                } else {
                    None
                };
                unsafe {
                    ((*UPCALLS).$func_name)(to_slots_closure(&mut self.factory));
                }
                if cfg!(feature = "roots_breakdown") {
                    let name = stringify!($struct_name);
                    let ms = t.unwrap().elapsed().unwrap().as_micros() as f32 / 1000f32;
                    report_roots(&name[4..name.len() - 5], ms);
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
scan_roots_work!(ScanWeakProcessorRoots, scan_weak_processor_roots);
scan_roots_work!(ScanVMThreadRoots, scan_vm_thread_roots);

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
        if cfg!(feature = "roots_breakdown") {
            record_roots(buf.len());
        }
        let factory: &mut F = unsafe { &mut *(factory_ptr as *mut F) };
        let kind = RootKind::Strong;
        factory.create_process_roots_work(buf, kind);
    }
    let (ptr, _, capacity) = {
        // TODO: Use Vec::into_raw_parts() when the method is available.
        use std::mem::ManuallyDrop;
        let new_vec = Vec::with_capacity(F::BUFFER_SIZE);
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

pub struct ScanCodeCacheRoots<S: Slot, F: RootsWorkFactory<S>> {
    factory: F,
    _p: PhantomData<S>,
}

impl<S: Slot, F: RootsWorkFactory<S>> ScanCodeCacheRoots<S, F> {
    pub fn new(factory: F) -> Self {
        Self {
            factory,
            _p: PhantomData,
        }
    }
}

impl<VM: VMBinding, F: RootsWorkFactory<VM::VMSlot>> GCWork<VM>
    for ScanCodeCacheRoots<VM::VMSlot, F>
{
    fn do_work(&mut self, _worker: &mut GCWorker<VM>, _mmtk: &'static MMTK<VM>) {
        let t = if cfg!(feature = "roots_breakdown") {
            Some(std::time::SystemTime::now())
        } else {
            None
        };
        let mut slots = Vec::with_capacity(F::BUFFER_SIZE);
        let mut mature = crate::MATURE_CODE_CACHE_ROOTS.lock().unwrap();
        let mut nursery_guard = crate::NURSERY_CODE_CACHE_ROOTS.lock().unwrap();
        let nursery = std::mem::take::<HashMap<Address, Vec<Address>>>(&mut nursery_guard);
        let mut c = 0;
        // mature roots
        for (key, roots) in mature.iter() {
            for r in roots {
                slots.push(VM::VMSlot::from_address(*r));
                if slots.len() >= F::BUFFER_SIZE {
                    if cfg!(feature = "roots_breakdown") {
                        c += slots.len();
                    }
                    self.factory
                        .create_process_roots_work(std::mem::take(&mut slots), RootKind::Strong);
                    slots.reserve(F::BUFFER_SIZE);
                }
            }
        }
        // Young roots
        for (key, roots) in nursery {
            for r in &roots {
                slots.push(VM::VMSlot::from_address(*r));
                if slots.len() >= F::BUFFER_SIZE {
                    if cfg!(feature = "roots_breakdown") {
                        c += slots.len();
                    }
                    self.factory
                        .create_process_roots_work(std::mem::take(&mut slots), RootKind::Strong);
                    slots.reserve(F::BUFFER_SIZE);
                }
            }
            mature.insert(key, roots);
        }
        if !slots.is_empty() {
            if cfg!(feature = "roots_breakdown") {
                c += slots.len();
            }
            self.factory
                .create_process_roots_work(slots, RootKind::Strong);
        }
        if cfg!(feature = "roots_breakdown") {
            let ms = t.unwrap().elapsed().unwrap().as_micros() as f32 / 1000f32;
            eprintln!(" - NewCodeCache roots count: {} ({:.3})", c, ms);
        }
    }
}
