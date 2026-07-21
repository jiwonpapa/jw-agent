use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

use zeroize::Zeroizing;

use crate::{PamError, PamSubject};

const PAM_SUCCESS: c_int = 0;
const PAM_OPEN_ERR: c_int = 1;
const PAM_SYSTEM_ERR: c_int = 4;
const PAM_CONV_ERR: c_int = 19;
const PAM_AUTH_ERR: c_int = 7;
const PAM_CRED_INSUFFICIENT: c_int = 8;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_USER_UNKNOWN: c_int = 10;
const PAM_MAXTRIES: c_int = 11;
const PAM_NEW_AUTHTOK_REQD: c_int = 12;
const PAM_ACCT_EXPIRED: c_int = 13;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;
const PAM_USER: c_int = 2;
const PAM_RHOST: c_int = 4;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 1;
const PAM_MAX_MESSAGES: usize = 32;

#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConversationFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConversation {
    conv: Option<ConversationFn>,
    appdata_ptr: *mut c_void,
}

struct ConversationState {
    password: *const c_char,
    password_bytes: usize,
    secret_prompt_count: usize,
    unsupported: bool,
}

#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service_name: *const c_char,
        user: *const c_char,
        conversation: *const PamConversation,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_set_item(pamh: *mut PamHandle, item_type: c_int, item: *const c_void) -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
}

pub fn authenticate(
    service: &str,
    username: &str,
    password: &str,
    remote_address: Option<&str>,
) -> Result<PamSubject, PamError> {
    let service = CString::new(service).map_err(|_| PamError::InvalidInput)?;
    let username = CString::new(username).map_err(|_| PamError::InvalidInput)?;
    if password.as_bytes().contains(&0) {
        return Err(PamError::InvalidInput);
    }

    let mut password_bytes = Zeroizing::new(password.as_bytes().to_vec());
    password_bytes.push(0);
    let mut state = ConversationState {
        password: password_bytes.as_ptr().cast(),
        password_bytes: password_bytes.len(),
        secret_prompt_count: 0,
        unsupported: false,
    };
    let state_pointer = ptr::from_mut(&mut state);
    let conversation = PamConversation {
        conv: Some(conversation),
        appdata_ptr: state_pointer.cast(),
    };
    let mut handle = ptr::null_mut();
    // SAFETY: all C strings and the conversation state remain alive through pam_end.
    let start_status = unsafe {
        pam_start(
            service.as_ptr(),
            username.as_ptr(),
            &conversation,
            &mut handle,
        )
    };
    if start_status != PAM_SUCCESS || handle.is_null() {
        return Err(map_status(start_status, state.unsupported));
    }

    let transaction = run_transaction(handle, remote_address, state_pointer);
    let (result, terminal_status) = match transaction {
        Ok(subject) => (Ok(subject), PAM_SUCCESS),
        Err((error, status)) => (Err(error), status),
    };
    // SAFETY: handle was returned by a successful pam_start and is ended exactly once.
    let end_status = unsafe { pam_end(handle, terminal_status) };
    if end_status != PAM_SUCCESS && result.is_ok() {
        Err(PamError::Unavailable)
    } else {
        result
    }
}

fn run_transaction(
    handle: *mut PamHandle,
    remote_address: Option<&str>,
    state: *const ConversationState,
) -> Result<PamSubject, (PamError, c_int)> {
    let remote = remote_address
        .map(CString::new)
        .transpose()
        .map_err(|_| (PamError::InvalidInput, PAM_SYSTEM_ERR))?;
    if let Some(remote) = &remote {
        // SAFETY: handle is live and remote is a NUL-terminated string for the duration of PAM.
        let status = unsafe { pam_set_item(handle, PAM_RHOST, remote.as_ptr().cast()) };
        if status != PAM_SUCCESS {
            return Err((map_status(status, conversation_unsupported(state)), status));
        }
    }

    // SAFETY: handle is live and the conversation callback owns bounded password responses.
    let auth_status = unsafe { pam_authenticate(handle, PAM_DISALLOW_NULL_AUTHTOK) };
    if auth_status != PAM_SUCCESS {
        return Err((
            map_status(auth_status, conversation_unsupported(state)),
            auth_status,
        ));
    }
    // SAFETY: handle is live and no session or credentials are opened by account management.
    let account_status = unsafe { pam_acct_mgmt(handle, PAM_DISALLOW_NULL_AUTHTOK) };
    if account_status != PAM_SUCCESS {
        return Err((
            map_account_status(account_status, conversation_unsupported(state)),
            account_status,
        ));
    }

    let mut item = ptr::null();
    // SAFETY: handle is live; PAM_USER is returned as a borrowed NUL-terminated string.
    let user_status = unsafe { pam_get_item(handle, PAM_USER, &mut item) };
    if user_status != PAM_SUCCESS || item.is_null() {
        return Err((PamError::Unavailable, user_status));
    }
    // SAFETY: successful pam_get_item(PAM_USER) returns a valid C string until pam_end.
    let canonical = unsafe { CStr::from_ptr(item.cast()) }
        .to_str()
        .map_err(|_| (PamError::Unavailable, PAM_SYSTEM_ERR))?
        .to_owned();
    Ok(PamSubject {
        canonical_username: canonical,
    })
}

fn conversation_unsupported(state: *const ConversationState) -> bool {
    // SAFETY: the pointer belongs to authenticate and is read only after a PAM call returns.
    unsafe { (*state).unsupported }
}

unsafe extern "C" fn conversation(
    message_count: c_int,
    messages: *mut *const PamMessage,
    responses: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if message_count <= 0 || messages.is_null() || responses.is_null() || appdata.is_null() {
        return PAM_CONV_ERR;
    }
    let Ok(count) = usize::try_from(message_count) else {
        return PAM_CONV_ERR;
    };
    if count > PAM_MAX_MESSAGES {
        return PAM_CONV_ERR;
    }
    // SAFETY: PAM provides an array with message_count entries for the callback duration.
    let message_slice = unsafe { std::slice::from_raw_parts(messages, count) };
    // SAFETY: calloc allocates a C-compatible zeroed response array owned by PAM on success.
    let allocated =
        unsafe { libc::calloc(count, std::mem::size_of::<PamResponse>()) }.cast::<PamResponse>();
    if allocated.is_null() {
        return PAM_CONV_ERR;
    }
    // SAFETY: appdata points to the live ConversationState created by authenticate.
    let state = unsafe { &mut *appdata.cast::<ConversationState>() };
    // SAFETY: allocated contains exactly count PamResponse entries.
    let response_slice = unsafe { std::slice::from_raw_parts_mut(allocated, count) };

    for (message_pointer, response) in message_slice.iter().zip(response_slice.iter_mut()) {
        if message_pointer.is_null() {
            state.unsupported = true;
            // SAFETY: allocated was returned by calloc and has not been transferred to PAM.
            unsafe { free_responses(allocated, count) };
            return PAM_CONV_ERR;
        }
        // SAFETY: non-null message pointers are valid for the callback duration.
        let message = unsafe { &**message_pointer };
        match message.msg_style {
            PAM_PROMPT_ECHO_OFF if state.secret_prompt_count == 0 => {
                state.secret_prompt_count += 1;
                // SAFETY: state password is NUL-terminated and password_bytes includes that NUL.
                let copy = unsafe { libc::malloc(state.password_bytes) }.cast::<c_char>();
                if copy.is_null() {
                    // SAFETY: allocated was returned by calloc and is still locally owned.
                    unsafe { free_responses(allocated, count) };
                    return PAM_CONV_ERR;
                }
                // SAFETY: source and destination are valid, non-overlapping password buffers.
                unsafe {
                    ptr::copy_nonoverlapping(state.password, copy, state.password_bytes);
                }
                response.resp = copy;
            }
            PAM_TEXT_INFO | PAM_ERROR_MSG => {}
            PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON | _ => {
                state.unsupported = true;
                // SAFETY: allocated was returned by calloc and is still locally owned.
                unsafe { free_responses(allocated, count) };
                return PAM_CONV_ERR;
            }
        }
    }
    // SAFETY: responses is valid and PAM assumes ownership of the allocated array on success.
    unsafe { *responses = allocated };
    PAM_SUCCESS
}

unsafe fn free_responses(responses: *mut PamResponse, count: usize) {
    // SAFETY: caller provides the live array allocated by calloc.
    let response_slice = unsafe { std::slice::from_raw_parts_mut(responses, count) };
    for response in response_slice {
        if !response.resp.is_null() {
            // SAFETY: resp is a live NUL-terminated password copy owned by this error path.
            unsafe { zero_c_string(response.resp) };
            // SAFETY: resp was allocated by malloc and has not been freed.
            unsafe { libc::free(response.resp.cast()) };
            response.resp = ptr::null_mut();
        }
    }
    // SAFETY: response array was allocated by calloc and has not been freed.
    unsafe { libc::free(responses.cast()) };
}

unsafe fn zero_c_string(value: *mut c_char) {
    // SAFETY: caller guarantees a live NUL-terminated C string.
    let length = unsafe { libc::strlen(value) };
    for offset in 0..length {
        // SAFETY: each offset is within the allocation before its terminal NUL.
        unsafe { ptr::write_volatile(value.add(offset), 0) };
    }
}

fn map_status(status: c_int, unsupported: bool) -> PamError {
    if unsupported || status == PAM_CONV_ERR {
        PamError::UnsupportedConversation
    } else {
        match status {
            PAM_AUTH_ERR | PAM_CRED_INSUFFICIENT | PAM_USER_UNKNOWN | PAM_MAXTRIES => {
                PamError::AuthenticationFailed
            }
            PAM_AUTHINFO_UNAVAIL | PAM_OPEN_ERR | PAM_SYSTEM_ERR => PamError::Unavailable,
            _ => PamError::Unavailable,
        }
    }
}

fn map_account_status(status: c_int, unsupported: bool) -> PamError {
    if unsupported || status == PAM_CONV_ERR {
        PamError::UnsupportedConversation
    } else {
        match status {
            PAM_NEW_AUTHTOK_REQD | PAM_ACCT_EXPIRED | PAM_AUTH_ERR | PAM_USER_UNKNOWN => {
                PamError::AccountDenied
            }
            _ => PamError::Unavailable,
        }
    }
}
