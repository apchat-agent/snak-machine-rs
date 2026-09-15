//! Allocation accounting is thread-local: parallel harness work is excluded.
use snac_rs::dns::wire::TcpFrames;
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
};
thread_local! { static ALLOCATED: Cell<Option<usize>> = const { Cell::new(None) }; }
struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCATED.with(|n| {
            if let Some(v) = n.get() {
                n.set(Some(v + l.size()));
            }
        });
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        ALLOCATED.with(|v| {
            if let Some(old) = v.get() {
                v.set(Some(old + n));
            }
        });
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static ALLOCATOR: Counting = Counting;
#[test]
fn s10_fragmented_frames_have_linear_allocation_and_atomic_rejection() {
    let message = vec![0x5a; 8192];
    let wire = TcpFrames::frame(&message).unwrap();
    let mut f = TcpFrames::new(65535).unwrap();
    ALLOCATED.with(|n| n.set(Some(0)));
    for byte in &wire {
        f.input(std::slice::from_ref(byte)).unwrap();
    }
    let allocated = ALLOCATED.with(|n| n.replace(None).unwrap());
    assert!(
        allocated < 2 * wire.len() + 2048,
        "fragmented input allocated {allocated} bytes"
    );
    assert_eq!(f.pop().unwrap(), message);
    assert_eq!(f.buffered(), 0);
    let small = TcpFrames::frame(&[0; 12]).unwrap();
    f.input(&small[..5]).unwrap();
    let mut invalid = small[5..].to_vec();
    invalid.extend([0, 1]);
    assert!(f.input(&invalid).is_err());
    assert_eq!(f.buffered(), 5);
    assert!(f.pop().is_none());
    f.input(&small[5..]).unwrap();
    assert_eq!(f.pop().unwrap(), vec![0; 12]);
}

#[test]
fn s10_declared_frame_storage_is_charged_before_allocation() {
    let mut f = TcpFrames::new(65535).unwrap();
    assert!(f.input_with_limit(&[0xff, 0xff], 8192).is_err());
    assert_eq!(f.buffered(), 0);
    assert_eq!(f.allocated(), 0);
    f.input_with_limit(&[0xff, 0xff], 65537).unwrap();
    assert_eq!(f.allocated(), 65537);
    let rest = vec![0; 65535];
    f.input_with_limit(&rest, 65537).unwrap();
    assert_eq!(f.allocated(), 65537);
    assert_eq!(f.pop().unwrap(), rest);
    assert_eq!(f.allocated(), 0);
    for _ in 0..32 {
        f.input(&[0, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
            .unwrap();
    }
    assert!(f.input(&[0xff, 0xff]).is_err());
    assert_eq!(f.buffered(), 32 * 14);
    assert_eq!(f.allocated(), 32 * 14);
}
