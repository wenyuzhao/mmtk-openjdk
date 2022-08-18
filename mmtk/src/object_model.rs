use std::sync::atomic::Ordering;

use super::UPCALLS;
use crate::abi::Oop;
use crate::{vm_metadata, OpenJDK};
use mmtk::util::alloc::fill_alignment_gap;
use mmtk::util::copy::*;
use mmtk::util::heap::layout::vm_layout_constants::HEAP_START;
use mmtk::util::metadata::header_metadata::HeaderMetadataSpec;
use mmtk::util::{Address, ObjectReference};
use mmtk::vm::*;

pub struct VMObjectModel {}

impl ObjectModel<OpenJDK> for VMObjectModel {
    // For now we use the default const from mmtk-core
    const GLOBAL_LOG_BIT_SPEC: VMGlobalLogBitSpec = vm_metadata::LOGGING_SIDE_METADATA_SPEC;

    const LOCAL_FORWARDING_POINTER_SPEC: VMLocalForwardingPointerSpec =
        vm_metadata::FORWARDING_POINTER_METADATA_SPEC;
    const LOCAL_FORWARDING_BITS_SPEC: VMLocalForwardingBitsSpec =
        vm_metadata::FORWARDING_BITS_METADATA_SPEC;
    const LOCAL_MARK_BIT_SPEC: VMLocalMarkBitSpec = vm_metadata::MARKING_METADATA_SPEC;
    const LOCAL_LOS_MARK_NURSERY_SPEC: VMLocalLOSMarkNurserySpec = vm_metadata::LOS_METADATA_SPEC;

    #[inline(always)]
    fn load_reference_field(slot: Address, root: bool) -> ObjectReference {
        if *crate::USE_COMPRESSED_OOPS {
            let narrow_root = slot.as_usize() & (1usize << 63) != 0;
            let slot = unsafe { Address::from_usize(slot.as_usize() << 1 >> 1) };
            if root && !narrow_root {
                unsafe { slot.load::<ObjectReference>() }
            } else {
                debug_assert!(root || !narrow_root);
                let v = unsafe { slot.load::<u32>() };
                if v == 0 {
                    ObjectReference::NULL
                } else {
                    unsafe { (HEAP_START + ((v as usize) << 3) - 4096).to_object_reference() }
                }
            }
        } else {
            unsafe { slot.load() }
        }
    }

    #[inline(always)]
    fn store_reference_field(slot: Address, object: ObjectReference, root: bool) {
        if *crate::USE_COMPRESSED_OOPS {
            let narrow_root = slot.as_usize() & (1usize << 63) != 0;
            let slot = unsafe { Address::from_usize(slot.as_usize() << 1 >> 1) };
            if root && !narrow_root {
                unsafe { slot.store(object) }
            } else {
                debug_assert!(root || !narrow_root);
                if object.is_null() {
                    unsafe { slot.store(0u32) };
                } else {
                    unsafe { slot.store(((object.to_address() - HEAP_START + 4096) >> 3) as u32) }
                }
            }
        } else {
            unsafe { slot.store(object) }
        }
    }

    #[inline(always)]
    fn load_metadata(
        metadata_spec: &HeaderMetadataSpec,
        object: ObjectReference,
        mask: Option<usize>,
        atomic_ordering: Option<Ordering>,
    ) -> usize {
        vm_metadata::load_metadata(metadata_spec, object, mask, atomic_ordering)
    }

    #[inline(always)]
    fn store_metadata(
        metadata_spec: &HeaderMetadataSpec,
        object: ObjectReference,
        val: usize,
        mask: Option<usize>,
        atomic_ordering: Option<Ordering>,
    ) {
        vm_metadata::store_metadata(metadata_spec, object, val, mask, atomic_ordering);
    }

    #[inline(always)]
    fn compare_exchange_metadata(
        metadata_spec: &HeaderMetadataSpec,
        object: ObjectReference,
        old_val: usize,
        new_val: usize,
        mask: Option<usize>,
        success_order: Ordering,
        failure_order: Ordering,
    ) -> bool {
        vm_metadata::compare_exchange_metadata(
            metadata_spec,
            object,
            old_val,
            new_val,
            mask,
            success_order,
            failure_order,
        )
    }

    #[inline(always)]
    fn fetch_add_metadata(
        metadata_spec: &HeaderMetadataSpec,
        object: ObjectReference,
        val: usize,
        order: Ordering,
    ) -> usize {
        vm_metadata::fetch_add_metadata(metadata_spec, object, val, order)
    }

    #[inline(always)]
    fn fetch_sub_metadata(
        metadata_spec: &HeaderMetadataSpec,
        object: ObjectReference,
        val: usize,
        order: Ordering,
    ) -> usize {
        vm_metadata::fetch_sub_metadata(metadata_spec, object, val, order)
    }

    #[inline]
    fn copy(
        from: ObjectReference,
        copy: CopySemantics,
        copy_context: &mut GCWorkerCopyContext<OpenJDK>,
    ) -> ObjectReference {
        let bytes = unsafe { Oop::from(from).size() };
        let dst = copy_context.alloc_copy(from, bytes, ::std::mem::size_of::<usize>(), 0, copy);
        // Copy
        let src = from.to_address();
        unsafe { std::ptr::copy_nonoverlapping::<u8>(src.to_ptr(), dst.to_mut_ptr(), bytes) }
        let to_obj = unsafe { dst.to_object_reference() };
        copy_context.post_copy(to_obj, bytes, copy);
        to_obj
    }

    fn copy_to(from: ObjectReference, to: ObjectReference, region: Address) -> Address {
        let need_copy = from != to;
        let bytes = unsafe { ((*UPCALLS).get_object_size)(from) };
        if need_copy {
            // copy obj to target
            let dst = to.to_address();
            // Copy
            let src = from.to_address();
            for i in 0..bytes {
                unsafe { (dst + i).store((src + i).load::<u8>()) };
            }
        }
        let start = Self::object_start_ref(to);
        if region != Address::ZERO {
            fill_alignment_gap::<OpenJDK>(region, start);
        }
        start + bytes
    }

    fn get_reference_when_copied_to(_from: ObjectReference, to: Address) -> ObjectReference {
        unsafe { to.to_object_reference() }
    }

    fn get_current_size(object: ObjectReference) -> usize {
        unsafe { Oop::from(object).size() }
    }

    fn get_size_when_copied(object: ObjectReference) -> usize {
        Self::get_current_size(object)
    }

    fn get_align_when_copied(_object: ObjectReference) -> usize {
        // FIXME figure out the proper alignment
        ::std::mem::size_of::<usize>()
    }

    fn get_align_offset_when_copied(_object: ObjectReference) -> isize {
        0
    }

    fn get_type_descriptor(_reference: ObjectReference) -> &'static [i8] {
        unimplemented!()
    }

    fn object_start_ref(object: ObjectReference) -> Address {
        object.to_address()
    }

    fn ref_to_address(object: ObjectReference) -> Address {
        object.to_address()
    }

    fn dump_object(object: ObjectReference) {
        unsafe {
            ((*UPCALLS).dump_object)(object);
        }
    }
}
