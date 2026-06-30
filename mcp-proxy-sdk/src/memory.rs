//! Linear-memory helpers for host/guest JSON exchange.

use crate::runtime::SdkError;
use crate::{INPUT_BUFFER_OFFSET, MAX_INPUT_BYTES};

/// Scratch region base offset — kept above the inbound evaluation buffer.
const SCRATCH_BASE: usize = 65536;

/// Scratch region capacity for outbound JSON strings.
const SCRATCH_CAPACITY: usize = 131072;

static mut SCRATCH: [u8; SCRATCH_CAPACITY] = [0; SCRATCH_CAPACITY];
static mut SCRATCH_NEXT: usize = 0;

/// Resets the outbound bump allocator at the start of each evaluation.
pub fn reset_scratch() {
    unsafe {
        SCRATCH_NEXT = 0;
    }
}

/// Reads the inbound JSON payload written by the host at [`INPUT_BUFFER_OFFSET`].
pub fn read_input(len: usize) -> Result<alloc::vec::Vec<u8>, SdkError> {
    if len > MAX_INPUT_BYTES {
        return Err(SdkError::InputTooLarge {
            len,
            max: MAX_INPUT_BYTES,
        });
    }

    unsafe {
        let ptr = INPUT_BUFFER_OFFSET as usize as *const u8;
        Ok(core::slice::from_raw_parts(ptr, len).to_vec())
    }
}

/// Copies `text` into guest scratch memory and returns `(ptr, len)` for host imports.
pub fn write_scratch(text: &str) -> Result<(*const u8, usize), SdkError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() {
        return Ok((SCRATCH_BASE as *const u8, 0));
    }

    unsafe {
        let start = SCRATCH_BASE
            .checked_add(SCRATCH_NEXT)
            .ok_or(SdkError::ScratchOverflow)?;
        let end = start
            .checked_add(bytes.len())
            .ok_or(SdkError::ScratchOverflow)?;

        if end > SCRATCH_BASE + SCRATCH_CAPACITY {
            return Err(SdkError::ScratchOverflow);
        }

        core::ptr::copy_nonoverlapping(
            bytes.as_ptr(),
            core::ptr::addr_of_mut!(SCRATCH).cast::<u8>().add(start),
            bytes.len(),
        );
        SCRATCH_NEXT = SCRATCH_NEXT.saturating_add(bytes.len());

        Ok((start as *const u8, bytes.len()))
    }
}
