use std::marker::PhantomData;
use std::sync::atomic::AtomicBool;
use std::sync::Mutex;

use crate::abi::{InstanceRefKlass, Oop, ReferenceType};
use crate::{OpenJDK, SINGLETON};
use atomic::{Atomic, Ordering};
use mmtk::scheduler::{GCWork, GCWorker, ProcessEdgesWork, WorkBucketStage};
use mmtk::util::opaque_pointer::VMWorkerThread;
use mmtk::util::{Address, ObjectReference};
use mmtk::vm::ReferenceGlue;
use mmtk::MMTK;

#[inline(always)]
pub fn set_referent(reff: ObjectReference, referent: ObjectReference) {
    let oop = Oop::from(reff);
    unsafe { InstanceRefKlass::referent_address(oop).store(referent) };
}

#[inline(always)]
fn get_referent(object: ObjectReference) -> ObjectReference {
    let oop = Oop::from(object);
    unsafe { InstanceRefKlass::referent_address(oop).load::<ObjectReference>() }
}

#[inline(always)]
fn get_next_reference_slot(object: ObjectReference) -> Address {
    let oop = Oop::from(object);
    InstanceRefKlass::discovered_address(oop)
}

#[inline(always)]
fn get_next_reference(object: ObjectReference) -> ObjectReference {
    unsafe { get_next_reference_slot(object).load() }
}

#[inline(always)]
fn set_next_reference(object: ObjectReference, next: ObjectReference) {
    unsafe { get_next_reference_slot(object).store(next) }
}

pub struct VMReferenceGlue {}

impl ReferenceGlue<OpenJDK> for VMReferenceGlue {
    type FinalizableType = ObjectReference;

    fn set_referent(reff: ObjectReference, referent: ObjectReference) {
        let oop = Oop::from(reff);
        unsafe { InstanceRefKlass::referent_address(oop).store(referent) };
    }
    fn get_referent(object: ObjectReference) -> ObjectReference {
        let oop = Oop::from(object);
        unsafe { InstanceRefKlass::referent_address(oop).load::<ObjectReference>() }
    }
    fn enqueue_references(_references: &[ObjectReference], _tls: VMWorkerThread) {
        // unsafe {
        //     ((*UPCALLS).enqueue_references)(references.as_ptr(), references.len());
        // }
    }
}

pub struct DiscoveredList {
    head: Atomic<ObjectReference>,
    _rt: ReferenceType,
}

impl DiscoveredList {
    fn new(rt: ReferenceType) -> Self {
        Self {
            head: Atomic::new(ObjectReference::NULL),
            _rt: rt,
        }
    }

    #[inline]
    pub fn add(&self, obj: ObjectReference) {
        let oop = Oop::from(obj);
        let head = self.head.load(Ordering::Relaxed);
        let discovered_addr = unsafe {
            InstanceRefKlass::discovered_address(oop).as_ref::<Atomic<ObjectReference>>()
        };
        let next_discovered = if head.is_null() { obj } else { head };
        debug_assert!(!next_discovered.is_null());
        if discovered_addr
            .compare_exchange(
                ObjectReference::NULL,
                next_discovered,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
        {
            // println!("add {:?} {:?}", self.rt, obj);
            self.head.store(obj, Ordering::Relaxed);
        }
        debug_assert!(!get_next_reference(obj).is_null());
    }
}

pub struct DiscoveredLists {
    pub soft: Vec<DiscoveredList>,
    pub weak: Vec<DiscoveredList>,
    pub r#final: Vec<DiscoveredList>,
    pub phantom: Vec<DiscoveredList>,
    allow_discover: AtomicBool,
}

impl DiscoveredLists {
    pub fn new() -> Self {
        let workers = crate::SINGLETON.scheduler.num_workers();
        let build_lists = |rt| (0..workers).map(|_| DiscoveredList::new(rt)).collect();
        Self {
            soft: build_lists(ReferenceType::Soft),
            weak: build_lists(ReferenceType::Weak),
            r#final: build_lists(ReferenceType::Final),
            phantom: build_lists(ReferenceType::Phantom),
            allow_discover: AtomicBool::new(true),
        }
    }

    #[inline]
    pub fn enable_discover(&self) {
        self.allow_discover.store(true, Ordering::SeqCst)
    }

    #[inline(always)]
    pub fn allow_discover(&self) -> bool {
        self.allow_discover.load(Ordering::SeqCst)
    }

    #[inline(always)]
    pub fn get_by_rt_and_index(&self, rt: ReferenceType, index: usize) -> &DiscoveredList {
        match rt {
            ReferenceType::Soft => &self.soft[index],
            ReferenceType::Weak => &self.weak[index],
            ReferenceType::Phantom => &self.phantom[index],
            ReferenceType::Final => &self.r#final[index],
            _ => unimplemented!(),
        }
    }

    #[inline(always)]
    pub fn get(&self, rt: ReferenceType) -> &DiscoveredList {
        let id = mmtk::scheduler::worker::current_worker_ordinal().unwrap();
        self.get_by_rt_and_index(rt, id)
    }

    pub fn process_lists<E: ProcessEdgesWork<VM = OpenJDK>>(
        &self,
        worker: &mut GCWorker<OpenJDK>,
        rt: ReferenceType,
        lists: &[DiscoveredList],
        clear: bool,
    ) {
        let mut packets = vec![];
        for i in 0..lists.len() {
            let head = lists[i].head.load(Ordering::SeqCst);
            if clear {
                lists[i].head.store(ObjectReference::NULL, Ordering::SeqCst);
            }
            if head.is_null() {
                continue;
            }
            let w = ProcessDiscoveredList {
                list_index: i,
                head,
                rt,
                _p: PhantomData::<E>,
            };
            packets.push(Box::new(w) as Box<dyn GCWork<OpenJDK>>);
        }
        worker.scheduler().work_buckets[WorkBucketStage::Unconstrained].bulk_add(packets);
    }

    pub fn reconsider_soft_refs<E: ProcessEdgesWork<VM = OpenJDK>>(
        &self,
        _worker: &mut GCWorker<OpenJDK>,
    ) {
    }

    pub fn process_soft_weak_final_refs<E: ProcessEdgesWork<VM = OpenJDK>>(
        &self,
        worker: &mut GCWorker<OpenJDK>,
    ) {
        self.allow_discover.store(false, Ordering::SeqCst);
        if !*SINGLETON.get_options().no_reference_types {
            self.process_lists::<E>(worker, ReferenceType::Soft, &self.soft, true);
            self.process_lists::<E>(worker, ReferenceType::Weak, &self.weak, true);
        }
        if !*SINGLETON.get_options().no_finalizer {
            self.process_lists::<E>(worker, ReferenceType::Final, &self.r#final, false);
        }
    }

    pub fn resurrect_final_refs<E: ProcessEdgesWork<VM = OpenJDK>>(
        &self,
        worker: &mut GCWorker<OpenJDK>,
    ) {
        assert!(!*SINGLETON.get_options().no_finalizer);
        let lists = &self.r#final;
        let mut packets = vec![];
        for i in 0..lists.len() {
            let head = lists[i].head.load(Ordering::SeqCst);
            lists[i].head.store(ObjectReference::NULL, Ordering::SeqCst);
            if head.is_null() {
                continue;
            }
            let w = ResurrectFinalizables {
                list_index: i,
                head,
                _p: PhantomData::<E>,
            };
            packets.push(Box::new(w) as Box<dyn GCWork<OpenJDK>>);
        }
        worker.scheduler().work_buckets[WorkBucketStage::Unconstrained].bulk_add(packets);
    }

    pub fn process_phantom_refs<E: ProcessEdgesWork<VM = OpenJDK>>(
        &self,
        worker: &mut GCWorker<OpenJDK>,
    ) {
        assert!(!*SINGLETON.get_options().no_reference_types);
        self.process_lists::<E>(worker, ReferenceType::Phantom, &self.phantom, true);
    }
}

lazy_static! {
    pub static ref LOCK: Mutex<()> = Mutex::new(());
    pub static ref DISCOVERED_LISTS: DiscoveredLists = DiscoveredLists::new();
}

pub struct ProcessDiscoveredList<E: ProcessEdgesWork<VM = OpenJDK>> {
    list_index: usize,
    head: ObjectReference,
    rt: ReferenceType,
    _p: PhantomData<E>,
}

impl<E: ProcessEdgesWork<VM = OpenJDK>> GCWork<OpenJDK> for ProcessDiscoveredList<E> {
    fn do_work(&mut self, worker: &mut GCWorker<OpenJDK>, mmtk: &'static MMTK<OpenJDK>) {
        let mut trace = E::new(vec![], false, mmtk);
        trace.set_worker(worker);
        let retain = self.rt == ReferenceType::Soft && !mmtk.get_plan().is_emergency_collection();
        let new_list = iterate_list(self.head, |reference| {
            let referent = get_referent(reference);
            if referent.is_null() {
                // Remove from the discovered list
                return IterationResult::Removed;
            } else if referent.is_live() || retain {
                // Keep this referent
                let forwarded = trace.trace_object(referent);
                set_referent(reference, forwarded);
                // Remove from the discovered list
                return IterationResult::Removed;
            } else {
                if self.rt != ReferenceType::Final {
                    // Clear this referent
                    set_referent(reference, ObjectReference::NULL);
                }
                // Keep the reference
                return IterationResult::Kept;
            }
        });
        // Flush the list to the Universe::pending_list
        if let Some((head, tail)) = new_list {
            assert!(!head.is_null() && !tail.is_null());
            assert_eq!(tail, get_next_reference(tail));
            if self.rt == ReferenceType::Final {
                DISCOVERED_LISTS.r#final[self.list_index]
                    .head
                    .store(head, Ordering::SeqCst);
            } else {
                let old_head = unsafe { ((*crate::UPCALLS).swap_reference_pending_list)(head) };
                set_next_reference(tail, old_head);
            }
        } else {
            if self.rt == ReferenceType::Final {
                DISCOVERED_LISTS.r#final[self.list_index]
                    .head
                    .store(ObjectReference::NULL, Ordering::SeqCst);
            }
        }
        trace.flush();
    }
}

pub struct ResurrectFinalizables<E: ProcessEdgesWork<VM = OpenJDK>> {
    list_index: usize,
    head: ObjectReference,
    _p: PhantomData<E>,
}

impl<E: ProcessEdgesWork<VM = OpenJDK>> GCWork<OpenJDK> for ResurrectFinalizables<E> {
    fn do_work(&mut self, worker: &mut GCWorker<OpenJDK>, mmtk: &'static MMTK<OpenJDK>) {
        let mut trace = E::new(vec![], false, mmtk);
        trace.set_worker(worker);
        let new_list = iterate_list(self.head, |reference| {
            let referent = get_referent(reference);
            let forwarded = trace.trace_object(referent);
            set_referent(reference, forwarded);
            return IterationResult::Kept;
        });

        if let Some((head, tail)) = new_list {
            assert!(!head.is_null() && !tail.is_null());
            assert_eq!(tail, get_next_reference(tail));
            DISCOVERED_LISTS.r#final[self.list_index]
                .head
                .store(ObjectReference::NULL, Ordering::SeqCst);
            let old_head = unsafe { ((*crate::UPCALLS).swap_reference_pending_list)(head) };
            set_next_reference(tail, old_head);
        }
        trace.flush();
    }
}

enum IterationResult {
    Kept,
    Removed,
}

fn iterate_list(
    mut head: ObjectReference,
    mut visitor: impl FnMut(ObjectReference) -> IterationResult,
) -> Option<(ObjectReference, ObjectReference)> {
    let mut cursor = &mut head;
    let mut holder: Option<ObjectReference> = None;
    let tail: Option<ObjectReference>;
    loop {
        debug_assert!(!cursor.is_null());
        let reference = *cursor;
        debug_assert!(reference.is_live());
        debug_assert!(reference.get_forwarded_object().is_none());
        let next_ref = get_next_reference(reference);
        let result = visitor(reference);
        match result {
            IterationResult::Removed => {
                // Remove `reference` from list
                let next_ref = get_next_reference(reference);
                set_next_reference(reference, ObjectReference::NULL);
                // Reached the end of the list?
                if next_ref.is_live() {
                    let next_ref = next_ref.get_forwarded_object().unwrap_or(next_ref);
                    if next_ref == reference {
                        // End of list
                        if let Some(holder) = holder {
                            set_next_reference(holder, holder);
                            tail = Some(holder);
                        } else {
                            *cursor = ObjectReference::NULL;
                            tail = None;
                        }
                        break;
                    }
                }
                // Move to next
                *cursor = next_ref;
            }
            IterationResult::Kept => {
                // Reached the end of the list?
                if next_ref.is_live() {
                    let next_ref = next_ref.get_forwarded_object().unwrap_or(next_ref);
                    if next_ref == reference {
                        // End of list
                        set_next_reference(reference, next_ref);
                        tail = Some(reference);
                        break;
                    }
                }
                // Move to next
                cursor = unsafe { &mut *get_next_reference_slot(reference).to_mut_ptr() };
                holder = Some(reference);
            }
        }
    }
    if head.is_null() {
        None
    } else {
        Some((head, tail.unwrap()))
    }
}
