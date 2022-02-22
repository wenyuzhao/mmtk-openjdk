use super::abi::*;
use super::UPCALLS;
use crate::{OpenJDK, SINGLETON};
use libc::c_char;
use mmtk::scheduler::ProcessEdgesWork;
use mmtk::scheduler::{GCWorker, WorkBucketStage};
use mmtk::util::constants::*;
use mmtk::util::opaque_pointer::*;
use mmtk::util::{Address, ObjectReference};
use mmtk::TransitiveClosure;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::{mem, slice};

trait OopIterate: Sized {
    fn do_metadata(&self) -> bool { false }
    fn oop_iterate(&self, oop: Oop, closure: &mut impl TransitiveClosure);
}

impl OopIterate for OopMapBlock {
    #[inline]
    fn oop_iterate(&self, oop: Oop, closure: &mut impl TransitiveClosure) {
        let start = oop.get_field_address(self.offset);
        for i in 0..self.count as usize {
            let edge = start + (i << LOG_BYTES_IN_ADDRESS);
            log(oop, edge);
            closure.process_edge(edge);
        }
    }
}

impl OopIterate for InstanceKlass {
    #[inline]
    fn oop_iterate(&self, oop: Oop, closure: &mut impl TransitiveClosure) {
        let oop_maps = self.nonstatic_oop_maps();
        for map in oop_maps {
            map.oop_iterate(oop, closure)
        }
    }
}

impl OopIterate for InstanceMirrorKlass {
    #[inline]
    fn do_metadata(&self) -> bool {
        true
    }
    #[inline]
    fn oop_iterate(&self, oop: Oop, closure: &mut impl TransitiveClosure) {
        self.instance_klass.oop_iterate(oop, closure);
        unsafe { ((*UPCALLS).scan_cld)(oop, process_edge as _) };
        unsafe {
            for e in EDGES.drain(..) {
                closure.process_edge(e)
            }
        }
        // if (Devirtualizer::do_metadata(closure)) {
        //     Klass* klass = java_lang_Class::as_Klass(obj);
        //     // We'll get NULL for primitive mirrors.
        //     if (klass != NULL) {
        //       if (klass->is_instance_klass() && InstanceKlass::cast(klass)->is_anonymous()) {
        //         // An anonymous class doesn't have its own class loader, so when handling
        //         // the java mirror for an anonymous class we need to make sure its class
        //         // loader data is claimed, this is done by calling do_cld explicitly.
        //         // For non-anonymous classes the call to do_cld is made when the class
        //         // loader itself is handled.
        //         Devirtualizer::do_cld(closure, klass->class_loader_data());
        //       } else {
        //         Devirtualizer::do_klass(closure, klass);
        //       }
        //     } else {
        //       // We would like to assert here (as below) that if klass has been NULL, then
        //       // this has been a mirror for a primitive type that we do not need to follow
        //       // as they are always strong roots.
        //       // However, we might get across a klass that just changed during CMS concurrent
        //       // marking if allocation occurred in the old generation.
        //       // This is benign here, as we keep alive all CLDs that were loaded during the
        //       // CMS concurrent phase in the class loading, i.e. they will be iterated over
        //       // and kept alive during remark.
        //       // assert(java_lang_Class::is_primitive(obj), "Sanity check");
        //     }
        // }

        // static fields
        let start: *const Oop = Self::start_of_static_fields(oop).to_ptr::<Oop>();
        let len = Self::static_oop_field_count(oop);
        let slice = unsafe { slice::from_raw_parts(start, len as _) };
        for x in slice {
            log(oop, Address::from_ref(x as &Oop));
            closure.process_edge(Address::from_ref(x as &Oop));
        }
    }
}

impl OopIterate for InstanceClassLoaderKlass {
    #[inline]
    fn do_metadata(&self) -> bool {
        true
    }
    #[inline]
    fn oop_iterate(&self, oop: Oop, closure: &mut impl TransitiveClosure) {
        self.instance_klass.oop_iterate(oop, closure);
        if self.do_metadata() {
            unsafe { ((*UPCALLS).scan_cld)(oop, process_edge as _) };
            unsafe {
                for e in EDGES.drain(..) {
                    closure.process_edge(e)
                }
            }
        }
        // if (Devirtualizer::do_metadata(closure)) {
        //     ClassLoaderData* cld = java_lang_ClassLoader::loader_data(obj);
        //     // cld can be null if we have a non-registered class loader.
        //     if (cld != NULL) {
        //         Devirtualizer::do_cld(closure, cld);
        //     }
        // }
    }
}

impl OopIterate for ObjArrayKlass {
    #[inline]
    fn oop_iterate(&self, oop: Oop, closure: &mut impl TransitiveClosure) {
        let array = unsafe { oop.as_array_oop::<Oop>() };
        for x in array.data() {
            log(oop, Address::from_ref(x as &Oop));
            closure.process_edge(Address::from_ref(x as &Oop));
        }
    }
}

impl OopIterate for TypeArrayKlass {
    #[inline]
    fn oop_iterate(&self, _oop: Oop, _closure: &mut impl TransitiveClosure) {
        // Performance tweak: We skip processing the klass pointer since all
        // TypeArrayKlasses are guaranteed processed via the null class loader.
    }
}

impl OopIterate for InstanceRefKlass {
    #[inline]
    fn oop_iterate(&self, oop: Oop, closure: &mut impl TransitiveClosure) {
        self.instance_klass.oop_iterate(oop, closure);
        let referent_addr = Self::referent_address(oop);
        log(oop, referent_addr);
        closure.process_edge(referent_addr);
        let discovered_addr = Self::discovered_address(oop);
        log(oop, discovered_addr);
        closure.process_edge(discovered_addr);
    }
}

#[allow(unused)]
fn oop_iterate_slow(oop: Oop, closure: &mut impl TransitiveClosure, tls: OpaquePointer) {
    unsafe {
        ((*UPCALLS).scan_object)(closure as *mut _ as _, mem::transmute(oop), tls);
    }
}

#[inline]
fn oop_iterate(oop: Oop, closure: &mut impl TransitiveClosure) {
    let klass_id = oop.klass.id;
    debug_assert!(
        klass_id as i32 >= 0 && (klass_id as i32) < 6,
        "Invalid klass-id: {:x} for oop: {:x}",
        klass_id as i32,
        unsafe { mem::transmute::<Oop, ObjectReference>(oop) }
    );
    match klass_id {
        KlassID::Instance => {
            let instance_klass = unsafe { oop.klass.cast::<InstanceKlass>() };
            instance_klass.oop_iterate(oop, closure);
        }
        KlassID::InstanceClassLoader => {
            let instance_klass = unsafe { oop.klass.cast::<InstanceClassLoaderKlass>() };
            instance_klass.oop_iterate(oop, closure);
        }
        KlassID::InstanceMirror => {
            let instance_klass = unsafe { oop.klass.cast::<InstanceMirrorKlass>() };
            instance_klass.oop_iterate(oop, closure);
        }
        KlassID::ObjArray => {
            let array_klass = unsafe { oop.klass.cast::<ObjArrayKlass>() };
            array_klass.oop_iterate(oop, closure);
        }
        KlassID::TypeArray => {
            let array_klass = unsafe { oop.klass.cast::<TypeArrayKlass>() };
            array_klass.oop_iterate(oop, closure);
        }
        KlassID::InstanceRef => {
            let instance_klass = unsafe { oop.klass.cast::<InstanceRefKlass>() };
            instance_klass.oop_iterate(oop, closure);
        } // _ => oop_iterate_slow(oop, closure, tls),
    }
}

#[inline]
pub fn scan_object(
    object: ObjectReference,
    closure: &mut impl TransitiveClosure,
    _tls: VMWorkerThread,
) {
    // println!("*****scan_object(0x{:x}) -> \n 0x{:x}, 0x{:x} \n",
    //     object,
    //     unsafe { *(object.value() as *const usize) },
    //     unsafe { *((object.value() + 8) as *const usize) }
    // );
    unsafe { oop_iterate(mem::transmute(object), closure) }
}

pub struct ObjectsClosure<'a, E: ProcessEdgesWork<VM = OpenJDK>>(
    Vec<Address>,
    &'a mut GCWorker<OpenJDK>,
    PhantomData<E>,
);

impl<'a, E: ProcessEdgesWork<VM = OpenJDK>> TransitiveClosure for ObjectsClosure<'a, E> {
    #[inline]
    fn process_edge(&mut self, slot: Address) {
        if self.0.is_empty() {
            self.0.reserve(E::CAPACITY);
        }
        self.0.push(slot);
        if self.0.len() >= E::CAPACITY {
            let mut new_edges = Vec::new();
            mem::swap(&mut new_edges, &mut self.0);
            self.1.add_work(
                WorkBucketStage::Closure,
                E::new(new_edges, false, &SINGLETON),
            );
        }
    }
    fn process_node(&mut self, _object: ObjectReference) {
        unreachable!()
    }
}

impl<'a, E: ProcessEdgesWork<VM = OpenJDK>> Drop for ObjectsClosure<'a, E> {
    #[inline]
    fn drop(&mut self) {
        let mut new_edges = Vec::new();
        mem::swap(&mut new_edges, &mut self.0);
        self.1.add_work(
            WorkBucketStage::Closure,
            E::new(new_edges, false, &SINGLETON),
        );
    }
}

pub fn scan_objects_and_create_edges_work<E: ProcessEdgesWork<VM = OpenJDK>>(
    objects: &[ObjectReference],
    worker: &mut GCWorker<OpenJDK>,
) {
    let mut closure = ObjectsClosure::<E>(Vec::new(), worker, PhantomData);
    for object in objects {
        scan_object(
            *object,
            &mut closure,
            VMWorkerThread(VMThread::UNINITIALIZED),
        );
    }
}

fn log(o: Oop, a: Address) {
    let x = unsafe {a.load::<ObjectReference>()};
    if x.is_null() {
        return;
    }
    let t = x.type_info::<OpenJDK>();
    // if t != "Lsun/awt/image/BufImgSurfaceManager;" &&  t != "Ljava/awt/image/BufferedImage;" {
    //     return;
    // }
    if t != "Ljava/awt/image/BufferedImage;" {
        return;
    }
    let s = {
        unsafe { ((*UPCALLS).get_oop_class_name)(mem::transmute(o), parse_string) };
        unsafe { S.take().unwrap() }
    };
    let u = format!("{} -> {} {}", s, t, a.as_usize() - o as *const _ as usize);
    *mmtk::EDGE_TYPES.lock().entry(u).or_insert(0) += 1;
    // println!("    - {} {:?} -> {} {:?}", s, o, t, x);
}

#[thread_local]
static mut S: Option<String> = None;

extern fn parse_string(s: *const c_char) {
    let c_str: &CStr = unsafe { CStr::from_ptr(s) };
    unsafe {
        S = Some(c_str.to_str().unwrap().to_owned())
    }
}

#[thread_local]
static mut EDGES: Vec<Address> = Vec::new();

#[thread_local]
extern fn process_edge(e: Address) {
    unsafe {
        EDGES.push(e)
    }
}
