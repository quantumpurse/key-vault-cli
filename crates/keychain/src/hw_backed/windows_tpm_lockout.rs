//! TPM 2.0 dictionary-attack state, read through TPM Base Services.
//!
//! NCrypt reports *that* an authorization failed, never what it cost. A wrong
//! PIN therefore arrives with no indication of how many attempts remain, and a
//! lockout with no indication of how long it lasts, which leaves a user who
//! mistyped their PIN nothing to act on.
//!
//! Those numbers are TPM capability properties, one layer below NCrypt, so
//! this module submits a raw `TPM2_GetCapability` through TBS to read them.
//! That command takes no authorization, so reading the counters cannot itself
//! move them.
//!
//! Everything here is best-effort. The numbers only enrich an error message,
//! so failing to read them degrades to a message without them rather than
//! replacing a clear "wrong PIN" with an obscure TBS error.

use core::ffi::c_void;
use core::ptr;
use windows_sys::Win32::System::TpmBaseServices::{
    Tbsi_Context_Create, Tbsip_Context_Close, Tbsip_Submit_Command, TBS_COMMAND_LOCALITY_ZERO,
    TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS, TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0,
    TBS_CONTEXT_VERSION_TWO, TBS_SUCCESS,
};

/// `TBS_CONTEXT_PARAMS2` carries a bitfield of `requestRaw`, `includeTpm12`
/// and `includeTpm20`. MSVC allocates bitfields from the least significant
/// bit, so asking for a TPM 2.0 context means setting bit 2.
const TBS_INCLUDE_TPM20: u32 = 1 << 2;

// TPM 2.0 wire encoding. Every integer is big-endian.
const TPM_ST_NO_SESSIONS: u16 = 0x8001;
const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;

/// The lockout properties are contiguous in the `TPM_PT_VAR` group, so a
/// single request starting at the counter returns all three.
///
/// `TPM_PT_LOCKOUT_RECOVERY` follows them and is deliberately not requested:
/// it times retries of `lockoutAuth`, the owner-authorization path, which is
/// not what a user hitting a wrong PIN is waiting on.
const TPM_PT_LOCKOUT_COUNTER: u32 = 0x0000_020E;
const TPM_PT_MAX_AUTH_FAIL: u32 = 0x0000_020F;
const TPM_PT_LOCKOUT_INTERVAL: u32 = 0x0000_0210;
const PROPERTY_COUNT: u32 = 3;

/// A `TPM2_GetCapability` command with no session area: a 10-byte header plus
/// capability, property and count.
const COMMAND_LEN: usize = 22;

/// A three-property reply occupies 43 bytes. Sized well above that so a chip
/// returning more than asked is truncated by the length TBS reports rather
/// than overflowing.
const RESPONSE_CAPACITY: usize = 1024;

// Response layout, from the start of the buffer.
const OFFSET_RESPONSE_CODE: usize = 6;
const OFFSET_CAPABILITY: usize = 11;
const OFFSET_PROPERTY_COUNT: usize = 15;
const OFFSET_FIRST_PROPERTY: usize = 19;
const PROPERTY_PAIR_LEN: usize = 8;

/// The chip's dictionary-attack counters at the moment they were read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct LockoutState {
    /// Failed authorizations recorded so far.
    pub counter: u32,
    /// Failures tolerated before the chip stops accepting authorizations.
    pub max_auth_fail: u32,
    /// Seconds before `counter` decreases by one.
    pub interval: u32,
}

impl LockoutState {
    /// Attempts left before lockout, or `None` when the chip reports a
    /// threshold of zero and the subtraction would be meaningless.
    pub(super) fn attempts_remaining(&self) -> Option<u32> {
        if self.max_auth_fail == 0 {
            return None;
        }
        Some(self.max_auth_fail.saturating_sub(self.counter))
    }
}

/// Renders a TPM interval as a duration phrase.
///
/// Zero is deliberately not special-cased into something like "immediately".
/// An interval of zero does not describe a short wait, so rendering it as a
/// duration risks telling the user the opposite of the truth;
/// [`heal_rate_sentence`] drops the claim instead.
pub(super) fn format_interval(seconds: u32) -> String {
    fn plural(n: u32, unit: &str) -> String {
        format!("{n} {unit}{}", if n == 1 { "" } else { "s" })
    }

    match seconds {
        s if s < 60 => plural(s, "second"),
        s if s < 3600 => plural(s / 60, "minute"),
        s => {
            let hours = plural(s / 3600, "hour");
            match (s % 3600) / 60 {
                0 => hours,
                minutes => format!("{hours} {}", plural(minutes, "minute")),
            }
        }
    }
}

/// Renders the healing rate as a sentence ready to append to a message, or an
/// empty string when the chip reports an interval that cannot be described.
///
/// The whole sentence is built here rather than interpolating
/// [`format_interval`] at each call site, so that only one place has to know
/// which intervals can legibly follow the word "every". Windows-managed chips
/// report intervals of hours, but the dictionary-attack parameters are chip
/// state an administrator can set, so the awkward values are reachable.
pub(super) fn heal_rate_sentence(seconds: u32) -> String {
    if seconds == 0 {
        return String::new();
    }
    format!(
        " It forgives one failed attempt every {}.",
        format_interval(seconds)
    )
}

/// Reads the lockout properties, or `None` if the TPM cannot be reached.
pub(super) fn read() -> Option<LockoutState> {
    let context = TbsContext::open()?;
    let response = context.submit(&get_capability_command())?;
    parse_lockout_properties(&response)
}

struct TbsContext(*mut c_void);

impl TbsContext {
    fn open() -> Option<Self> {
        let params = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            Anonymous: TBS_CONTEXT_PARAMS2_0 {
                asUINT32: TBS_INCLUDE_TPM20,
            },
        };
        let mut handle: *mut c_void = ptr::null_mut();
        // TBS_CONTEXT_PARAMS2 extends TBS_CONTEXT_PARAMS; the shared leading
        // `version` field is what tells TBS which layout it was handed.
        let rc = unsafe {
            Tbsi_Context_Create(
                (&params as *const TBS_CONTEXT_PARAMS2).cast::<TBS_CONTEXT_PARAMS>(),
                &mut handle,
            )
        };
        if rc != TBS_SUCCESS || handle.is_null() {
            return None;
        }
        Some(Self(handle))
    }

    fn submit(&self, command: &[u8]) -> Option<Vec<u8>> {
        let mut response = vec![0u8; RESPONSE_CAPACITY];
        let mut response_len = RESPONSE_CAPACITY as u32;
        let rc = unsafe {
            Tbsip_Submit_Command(
                self.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command.len() as u32,
                response.as_mut_ptr(),
                &mut response_len,
            )
        };
        if rc != TBS_SUCCESS {
            return None;
        }
        response.truncate(response_len as usize);
        Some(response)
    }
}

impl Drop for TbsContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { Tbsip_Context_Close(self.0) };
        }
    }
}

fn get_capability_command() -> [u8; COMMAND_LEN] {
    let mut command = [0u8; COMMAND_LEN];
    command[0..2].copy_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
    command[2..6].copy_from_slice(&(COMMAND_LEN as u32).to_be_bytes());
    command[6..10].copy_from_slice(&TPM_CC_GET_CAPABILITY.to_be_bytes());
    command[10..14].copy_from_slice(&TPM_CAP_TPM_PROPERTIES.to_be_bytes());
    command[14..18].copy_from_slice(&TPM_PT_LOCKOUT_COUNTER.to_be_bytes());
    command[18..22].copy_from_slice(&PROPERTY_COUNT.to_be_bytes());
    command
}

/// Parses a `TPM2_GetCapability` reply.
///
/// Properties are matched by tag rather than by position. A TPM is permitted
/// to return fewer properties than requested, and reading them positionally
/// would then silently mislabel the values it did return.
fn parse_lockout_properties(response: &[u8]) -> Option<LockoutState> {
    if be_u32(response, OFFSET_RESPONSE_CODE)? != 0 {
        return None;
    }
    if be_u32(response, OFFSET_CAPABILITY)? != TPM_CAP_TPM_PROPERTIES {
        return None;
    }
    let count = be_u32(response, OFFSET_PROPERTY_COUNT)? as usize;

    let mut counter = None;
    let mut max_auth_fail = None;
    let mut interval = None;

    for index in 0..count {
        let at = OFFSET_FIRST_PROPERTY + index * PROPERTY_PAIR_LEN;
        let property = be_u32(response, at)?;
        let value = be_u32(response, at + 4)?;
        match property {
            TPM_PT_LOCKOUT_COUNTER => counter = Some(value),
            TPM_PT_MAX_AUTH_FAIL => max_auth_fail = Some(value),
            TPM_PT_LOCKOUT_INTERVAL => interval = Some(value),
            _ => {}
        }
    }

    Some(LockoutState {
        counter: counter?,
        max_auth_fail: max_auth_fail?,
        interval: interval?,
    })
}

fn be_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at + 4)?;
    Some(u32::from_be_bytes(field.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a reply in the shape a TPM returns, so the offset constants are
    /// pinned by a test rather than by inspection of the specification.
    fn response(response_code: u32, capability: u32, pairs: &[(u32, u32)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TPM_ST_NO_SESSIONS.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes()); // responseSize, not read
        bytes.extend_from_slice(&response_code.to_be_bytes());
        bytes.push(0); // moreData
        bytes.extend_from_slice(&capability.to_be_bytes());
        bytes.extend_from_slice(&(pairs.len() as u32).to_be_bytes());
        for (property, value) in pairs {
            bytes.extend_from_slice(&property.to_be_bytes());
            bytes.extend_from_slice(&value.to_be_bytes());
        }
        bytes
    }

    fn all_properties() -> Vec<(u32, u32)> {
        vec![
            (TPM_PT_LOCKOUT_COUNTER, 3),
            (TPM_PT_MAX_AUTH_FAIL, 32),
            (TPM_PT_LOCKOUT_INTERVAL, 7200),
        ]
    }

    #[test]
    fn command_is_a_well_formed_get_capability() {
        let command = get_capability_command();
        assert_eq!(command.len(), COMMAND_LEN);
        assert_eq!(&command[0..2], &TPM_ST_NO_SESSIONS.to_be_bytes());
        // The declared size must match the bytes actually sent, or the TPM
        // rejects the command outright.
        assert_eq!(
            u32::from_be_bytes(command[2..6].try_into().unwrap()),
            COMMAND_LEN as u32
        );
        assert_eq!(
            u32::from_be_bytes(command[6..10].try_into().unwrap()),
            TPM_CC_GET_CAPABILITY
        );
        assert_eq!(
            u32::from_be_bytes(command[18..22].try_into().unwrap()),
            PROPERTY_COUNT
        );
    }

    #[test]
    fn parses_every_requested_property() {
        let state =
            parse_lockout_properties(&response(0, TPM_CAP_TPM_PROPERTIES, &all_properties()))
                .unwrap();
        assert_eq!(
            state,
            LockoutState {
                counter: 3,
                max_auth_fail: 32,
                interval: 7200,
            }
        );
        assert_eq!(state.attempts_remaining(), Some(29));
    }

    #[test]
    fn parses_properties_returned_out_of_order() {
        let mut pairs = all_properties();
        pairs.reverse();
        let state = parse_lockout_properties(&response(0, TPM_CAP_TPM_PROPERTIES, &pairs)).unwrap();
        assert_eq!(state.counter, 3);
        assert_eq!(state.max_auth_fail, 32);
    }

    #[test]
    fn ignores_unrequested_properties() {
        let mut pairs = all_properties();
        pairs.insert(0, (0x0000_0100, 999));
        assert!(parse_lockout_properties(&response(0, TPM_CAP_TPM_PROPERTIES, &pairs)).is_some());
    }

    #[test]
    fn rejects_a_tpm_error_response() {
        assert!(parse_lockout_properties(&response(
            0x0000_0921,
            TPM_CAP_TPM_PROPERTIES,
            &all_properties()
        ))
        .is_none());
    }

    #[test]
    fn rejects_a_mismatched_capability() {
        assert!(parse_lockout_properties(&response(0, 0x0000_0001, &all_properties())).is_none());
    }

    #[test]
    fn rejects_a_partial_property_set() {
        let pairs = vec![(TPM_PT_LOCKOUT_COUNTER, 3), (TPM_PT_MAX_AUTH_FAIL, 32)];
        assert!(parse_lockout_properties(&response(0, TPM_CAP_TPM_PROPERTIES, &pairs)).is_none());
    }

    #[test]
    fn rejects_a_truncated_response() {
        let full = response(0, TPM_CAP_TPM_PROPERTIES, &all_properties());
        for len in 0..full.len() {
            assert!(
                parse_lockout_properties(&full[..len]).is_none(),
                "accepted a response truncated to {len} bytes"
            );
        }
    }

    #[test]
    fn rejects_a_count_larger_than_the_payload() {
        let mut bytes = response(0, TPM_CAP_TPM_PROPERTIES, &all_properties());
        bytes[OFFSET_PROPERTY_COUNT..OFFSET_PROPERTY_COUNT + 4]
            .copy_from_slice(&99u32.to_be_bytes());
        assert!(parse_lockout_properties(&bytes).is_none());
    }

    #[test]
    fn attempts_remaining_saturates_past_the_threshold() {
        let state = LockoutState {
            counter: 40,
            max_auth_fail: 32,
            interval: 7200,
        };
        assert_eq!(state.attempts_remaining(), Some(0));
    }

    #[test]
    fn attempts_remaining_is_unknown_without_a_threshold() {
        let state = LockoutState {
            counter: 1,
            max_auth_fail: 0,
            interval: 7200,
        };
        assert_eq!(state.attempts_remaining(), None);
    }

    #[test]
    fn intervals_read_as_prose() {
        assert_eq!(format_interval(1), "1 second");
        assert_eq!(format_interval(30), "30 seconds");
        assert_eq!(format_interval(60), "1 minute");
        assert_eq!(format_interval(600), "10 minutes");
        assert_eq!(format_interval(3600), "1 hour");
        assert_eq!(format_interval(7200), "2 hours");
        assert_eq!(format_interval(7500), "2 hours 5 minutes");
    }

    /// Every non-empty heal rate has to read correctly after the preceding
    /// sentence, which is what makes the zero case an omission rather than a
    /// phrase.
    #[test]
    fn heal_rate_reads_as_a_sentence() {
        assert_eq!(heal_rate_sentence(0), "");
        assert_eq!(
            heal_rate_sentence(30),
            " It forgives one failed attempt every 30 seconds."
        );
        assert_eq!(
            heal_rate_sentence(7200),
            " It forgives one failed attempt every 2 hours."
        );
    }
}
