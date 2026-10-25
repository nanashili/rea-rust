//! Owned safe wrapper over `frida-sys`.
//!
//! Ownership model:
//! - [`Runtime`] owns one dedicated thread. That thread calls `frida_init`,
//!   pushes frida's main `GMainContext` as its thread default (see `start`) and
//!   iterates it between commands. Every frida-core `*_sync` call and every free runs on
//!   that thread through the command channel, each with a `GCancellable`
//!   ([`Cancel`]) that any thread may trigger.
//! - Every wrapper handle holds an `Arc<Runtime>`, so the owner thread outlives
//!   all handles. Dropping a handle enqueues its release on the owner thread;
//!   signal handlers are disconnected before the final unref.
//! - Signal callbacks (`detached`, `message`) are emitted by frida-core on its
//!   own context; they only copy data into an `mpsc::Sender` owned by the
//!   closure (freed by the closure's destroy notify).
//!
//! If the owner thread is gone (it panicked), handles are intentionally
//! leaked rather than freed on a foreign thread.

use std::ffi::{CStr, CString, c_char, c_void};
use std::path::PathBuf;
use std::ptr;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use frida_sys as sys;

/// Expected failure of a wrapper operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FfiError {
    /// The call's `GCancellable` was triggered.
    Cancelled,
    /// frida-core / GLib reported a `GError`.
    Frida { code: i32, message: String },
    /// An argument cannot cross the C boundary (interior NUL, bad length).
    InvalidArgument(String),
    /// The owner thread is no longer running.
    RuntimeGone,
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => f.write_str("operation was cancelled"),
            Self::Frida { message, .. } => f.write_str(message),
            Self::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Self::RuntimeGone => f.write_str("frida runtime thread is not running"),
        }
    }
}

pub(crate) type FfiResult<T> = Result<T, FfiError>;

/// A raw pointer that is only dereferenced on the owner thread.
struct Raw<T>(*mut T);
// SAFETY: the pointee is only touched on the runtime thread (or through
// GLib's documented thread-safe entry points such as `g_cancellable_cancel`).
unsafe impl<T> Send for Raw<T> {}
unsafe impl<T> Sync for Raw<T> {}
impl<T> Raw<T> {
    /// Method access forces closures to capture the whole `Send` wrapper.
    fn get(&self) -> *mut T {
        self.0
    }
}
impl<T> Clone for Raw<T> {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}
impl<T> Copy for Raw<T> {}

type Command = Box<dyn FnOnce() + Send>;

/// The owned frida/GLib thread.
pub(crate) struct Runtime {
    tx: Mutex<Option<Sender<Command>>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Runtime {
    pub(crate) fn start() -> FfiResult<Arc<Self>> {
        let (tx, rx) = mpsc::channel::<Command>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(1);
        let thread = std::thread::Builder::new()
            .name("rea-frida".into())
            .spawn(move || {
                // SAFETY: frida_init is idempotent; the context is created,
                // pushed, popped and released on this thread only.
                //
                // The thread-default context is frida's own main context:
                // frida-core objects bind async completions to their creator's
                // thread-default context, and this thread blocks inside every
                // `*_sync` call, so a private context would never be iterated
                // and the first sync call deadlocks (observed). frida's
                // `frida-main-loop` thread iterates it; our iteration below is
                // a no-op while that thread owns it.
                let ctx = unsafe {
                    sys::frida_init();
                    let ctx = sys::g_main_context_ref(sys::frida_get_main_context());
                    sys::g_main_context_push_thread_default(ctx);
                    ctx
                };
                let _ = ready_tx.send(());
                loop {
                    match rx.recv_timeout(Duration::from_millis(20)) {
                        Ok(cmd) => cmd(),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => break,
                    }
                    // SAFETY: ctx is this thread's live default context.
                    while unsafe { sys::g_main_context_iteration(ctx, 0) } != 0 {}
                }
                // SAFETY: matching pop/unref for the push/new above.
                unsafe {
                    sys::g_main_context_pop_thread_default(ctx);
                    sys::g_main_context_unref(ctx);
                }
            })
            .map_err(|e| FfiError::InvalidArgument(format!("spawn frida thread: {e}")))?;
        ready_rx.recv().map_err(|_| FfiError::RuntimeGone)?;
        Ok(Arc::new(Self {
            tx: Mutex::new(Some(tx)),
            thread: Mutex::new(Some(thread)),
        }))
    }

    fn post(&self, cmd: Command) -> bool {
        let guard = self.tx.lock().unwrap_or_else(|p| p.into_inner());
        guard.as_ref().is_some_and(|tx| tx.send(cmd).is_ok())
    }

    /// Run `f` on the owner thread and wait for its result.
    fn run<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> FfiResult<T> {
        let (tx, rx) = mpsc::sync_channel(1);
        if !self.post(Box::new(move || {
            let _ = tx.send(f());
        })) {
            return Err(FfiError::RuntimeGone);
        }
        rx.recv().map_err(|_| FfiError::RuntimeGone)
    }

    /// Enqueue a release on the owner thread; leak if the thread is gone.
    fn release(&self, f: impl FnOnce() + Send + 'static) {
        let _ = self.post(Box::new(f));
    }

    /// A fresh `GCancellable` for one or more calls.
    pub(crate) fn cancellable(self: &Arc<Self>) -> FfiResult<Cancel> {
        // SAFETY: g_cancellable_new has no preconditions.
        let raw = self.run(|| Raw(unsafe { sys::g_cancellable_new() }))?;
        Ok(Cancel(Arc::new(CancelInner {
            raw,
            rt: Arc::clone(self),
        })))
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.tx.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(t) = self.thread.lock().unwrap_or_else(|p| p.into_inner()).take() {
            // Dropped from the owner thread itself (last handle released in a
            // command): the loop exits on its own once the sender is gone.
            if t.thread().id() != std::thread::current().id() {
                let _ = t.join();
            }
        }
    }
}

struct CancelInner {
    raw: Raw<sys::GCancellable>,
    rt: Arc<Runtime>,
}

impl Drop for CancelInner {
    fn drop(&mut self) {
        let raw = self.raw;
        // SAFETY: we own one reference.
        self.rt
            .release(move || unsafe { sys::g_object_unref(raw.get().cast()) });
    }
}

/// Cancellation handle for frida calls; clone and `cancel()` from any thread.
#[derive(Clone)]
pub(crate) struct Cancel(Arc<CancelInner>);

impl Cancel {
    pub(crate) fn cancel(&self) {
        // SAFETY: g_cancellable_cancel is documented thread-safe and the
        // object stays alive while `self` holds its reference.
        unsafe { sys::g_cancellable_cancel(self.0.raw.get()) }
    }
    pub(crate) fn is_cancelled(&self) -> bool {
        // SAFETY: as above.
        unsafe { sys::g_cancellable_is_cancelled(self.0.raw.get()) != 0 }
    }
}

/// Run one `*_sync` call on the owner thread with `cancel`'s `GCancellable`.
fn call<T: Send + 'static>(
    rt: &Runtime,
    cancel: &Cancel,
    f: impl FnOnce(*mut sys::GCancellable, *mut *mut sys::GError) -> T + Send + 'static,
) -> FfiResult<T> {
    let keep = cancel.clone();
    rt.run(move || {
        let mut err: *mut sys::GError = ptr::null_mut();
        let out = f(keep.0.raw.get(), &mut err);
        // SAFETY: `err` is null or a GError we now own.
        unsafe { take_error(err, &keep) }.map(|()| out)
    })?
}

/// SAFETY: `err` must be null or an owned `GError`.
unsafe fn take_error(err: *mut sys::GError, cancel: &Cancel) -> FfiResult<()> {
    if err.is_null() {
        return Ok(());
    }
    // SAFETY: non-null owned GError per contract.
    let (code, message) = unsafe { ((*err).code, cstr((*err).message)) };
    unsafe { sys::g_error_free(err) };
    if cancel.is_cancelled() {
        Err(FfiError::Cancelled)
    } else {
        Err(FfiError::Frida { code, message })
    }
}

fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        String::new()
    } else {
        // SAFETY: frida/GLib strings are NUL-terminated.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }
}

fn cstring(field: &str, s: &str) -> FfiResult<CString> {
    CString::new(s).map_err(|_| FfiError::InvalidArgument(format!("{field} contains NUL")))
}

/// SAFETY: must run on the owner thread; `gtype` is a registered enum type.
unsafe fn enum_nick(gtype: sys::GType, value: i32) -> String {
    unsafe {
        let class = sys::g_type_class_ref(gtype);
        let v = sys::g_enum_get_value(class.cast(), value);
        let out = if v.is_null() {
            value.to_string()
        } else {
            cstr((*v).value_nick)
        };
        sys::g_type_class_unref(class);
        out
    }
}

/// Unref on the owner thread after disconnecting `handler` (if any).
fn release_object<T: 'static>(rt: &Runtime, obj: Raw<T>, handler: Option<u64>) {
    rt.release(move || unsafe {
        // SAFETY: handler was connected on this instance; we own one ref.
        if let Some(id) = handler {
            sys::g_signal_handler_disconnect(obj.get().cast(), id as _);
        }
        sys::g_object_unref(obj.get().cast());
    });
}

/// Connect `cb` to `signal`, transferring `sender` to the closure.
///
/// SAFETY: owner thread; `cb` must match the signal's C signature with the
/// boxed `Sender<E>` as last argument.
unsafe fn connect<E>(
    instance: *mut c_void,
    signal: &CStr,
    cb: *const (),
    sender: Sender<E>,
) -> u64 {
    unsafe extern "C" fn destroy<E>(data: *mut c_void, _: *mut sys::GClosure) {
        // SAFETY: data is the Box leaked below; GLib calls this exactly once.
        drop(unsafe { Box::from_raw(data.cast::<Sender<E>>()) });
    }
    let data = Box::into_raw(Box::new(sender)).cast::<c_void>();
    // SAFETY: GCallback is an untyped function pointer by GLib convention.
    let cb: unsafe extern "C" fn() = unsafe { std::mem::transmute(cb) };
    unsafe {
        sys::g_signal_connect_data(
            instance,
            signal.as_ptr(),
            Some(cb),
            data,
            Some(destroy::<E>),
            sys::GConnectFlags_G_CONNECT_DEFAULT,
        ) as u64
    }
}

// ---------------------------------------------------------------------------
// DeviceManager

pub(crate) struct DeviceManager {
    raw: Raw<sys::FridaDeviceManager>,
    rt: Arc<Runtime>,
}

/// TLS certificate source for a remote device.
#[derive(Debug, Clone)]
pub(crate) enum Certificate {
    Pem(String),
    File(PathBuf),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct RemoteOptions {
    pub token: Option<String>,
    pub certificate: Option<Certificate>,
    pub origin: Option<String>,
    pub keepalive_interval: Option<i32>,
}

impl DeviceManager {
    pub(crate) fn new(rt: &Arc<Runtime>) -> FfiResult<Self> {
        // SAFETY: owner thread, no preconditions.
        let raw = rt.run(|| Raw(unsafe { sys::frida_device_manager_new() }))?;
        Ok(Self {
            raw,
            rt: Arc::clone(rt),
        })
    }

    fn device(&self, raw: *mut sys::FridaDevice) -> Device {
        Device {
            raw: Raw(raw),
            rt: Arc::clone(&self.rt),
        }
    }

    pub(crate) fn enumerate_devices(&self, cancel: &Cancel) -> FfiResult<Vec<Device>> {
        let m = self.raw;
        let raws = call(&self.rt, cancel, move |c, e| unsafe {
            // SAFETY: owner thread; list items are transfer-full refs.
            let list = sys::frida_device_manager_enumerate_devices_sync(m.get(), c, e);
            if list.is_null() {
                return Vec::new();
            }
            let n = sys::frida_device_list_size(list);
            let v = (0..n)
                .map(|i| Raw(sys::frida_device_list_get(list, i)))
                .collect::<Vec<_>>();
            sys::g_object_unref(list.cast());
            v
        })?;
        Ok(raws.into_iter().map(|r| self.device(r.get())).collect())
    }

    /// `timeout_ms`: frida semantics (`-1` waits indefinitely, `0` no wait).
    pub(crate) fn get_device_by_id(
        &self,
        id: &str,
        timeout_ms: i32,
        cancel: &Cancel,
    ) -> FfiResult<Device> {
        let id = cstring("device id", id)?;
        let m = self.raw;
        // SAFETY: owner thread; returns a transfer-full ref or sets error.
        let r = call(&self.rt, cancel, move |c, e| {
            Raw(unsafe {
                sys::frida_device_manager_get_device_by_id_sync(
                    m.get(),
                    id.as_ptr(),
                    timeout_ms,
                    c,
                    e,
                )
            })
        })?;
        Ok(self.device(r.get()))
    }

    pub(crate) fn add_remote_device(
        &self,
        address: &str,
        opts: &RemoteOptions,
        cancel: &Cancel,
    ) -> FfiResult<Device> {
        let address = cstring("address", address)?;
        let token = opts
            .token
            .as_deref()
            .map(|t| cstring("token", t))
            .transpose()?;
        let origin = opts
            .origin
            .as_deref()
            .map(|o| cstring("origin", o))
            .transpose()?;
        let cert = match &opts.certificate {
            None => None,
            Some(Certificate::Pem(p)) => Some((true, cstring("certificate", p)?)),
            Some(Certificate::File(f)) => {
                Some((false, cstring("certificate path", &f.to_string_lossy())?))
            }
        };
        let keepalive = opts.keepalive_interval;
        let m = self.raw;
        let keep = cancel.clone();
        let r = self.rt.run(move || unsafe {
            // SAFETY: owner thread; option setters copy/ref their inputs.
            let o = sys::frida_remote_device_options_new();
            let mut err: *mut sys::GError = ptr::null_mut();
            if let Some((pem, s)) = &cert {
                let tls = if *pem {
                    sys::g_tls_certificate_new_from_pem(s.as_ptr(), -1, &mut err)
                } else {
                    sys::g_tls_certificate_new_from_file(s.as_ptr(), &mut err)
                };
                if tls.is_null() {
                    sys::g_object_unref(o.cast());
                    return take_error(err, &keep)
                        .and(Err(FfiError::InvalidArgument("certificate".into())));
                }
                sys::frida_remote_device_options_set_certificate(o, tls);
                sys::g_object_unref(tls.cast());
            }
            if let Some(t) = &token {
                sys::frida_remote_device_options_set_token(o, t.as_ptr());
            }
            if let Some(s) = &origin {
                sys::frida_remote_device_options_set_origin(o, s.as_ptr());
            }
            if let Some(k) = keepalive {
                sys::frida_remote_device_options_set_keepalive_interval(o, k);
            }
            let d = sys::frida_device_manager_add_remote_device_sync(
                m.get(),
                address.as_ptr(),
                o,
                keep.0.raw.get(),
                &mut err,
            );
            sys::g_object_unref(o.cast());
            take_error(err, &keep).map(|()| Raw(d))
        })??;
        Ok(self.device(r.get()))
    }

    pub(crate) fn remove_remote_device(&self, address: &str, cancel: &Cancel) -> FfiResult<()> {
        let address = cstring("address", address)?;
        let m = self.raw;
        // SAFETY: owner thread.
        call(&self.rt, cancel, move |c, e| unsafe {
            sys::frida_device_manager_remove_remote_device_sync(m.get(), address.as_ptr(), c, e)
        })
    }
}

impl Drop for DeviceManager {
    fn drop(&mut self) {
        let m = self.raw;
        self.rt.release(move || unsafe {
            // SAFETY: owner thread; close then drop our reference.
            let mut err: *mut sys::GError = ptr::null_mut();
            sys::frida_device_manager_close_sync(m.get(), ptr::null_mut(), &mut err);
            if !err.is_null() {
                sys::g_error_free(err);
            }
            sys::g_object_unref(m.get().cast());
        });
    }
}

// ---------------------------------------------------------------------------
// Device

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessInfo {
    pub pid: u32,
    pub name: String,
}

pub(crate) struct Device {
    raw: Raw<sys::FridaDevice>,
    rt: Arc<Runtime>,
}

/// SAFETY: owner thread; `p` is a live FridaProcess.
unsafe fn process_info(p: *mut sys::FridaProcess) -> ProcessInfo {
    unsafe {
        ProcessInfo {
            pid: sys::frida_process_get_pid(p),
            name: cstr(sys::frida_process_get_name(p)),
        }
    }
}

impl Device {
    /// `(id, name, type nick)` read on the owner thread.
    pub(crate) fn describe(&self) -> FfiResult<(String, String, String)> {
        let d = self.raw;
        self.rt.run(move || unsafe {
            // SAFETY: owner thread; getters return borrowed strings.
            (
                cstr(sys::frida_device_get_id(d.get())),
                cstr(sys::frida_device_get_name(d.get())),
                enum_nick(
                    sys::frida_device_type_get_type(),
                    sys::frida_device_get_dtype(d.get()) as i32,
                ),
            )
        })
    }

    pub(crate) fn enumerate_processes(&self, cancel: &Cancel) -> FfiResult<Vec<ProcessInfo>> {
        let d = self.raw;
        call(&self.rt, cancel, move |c, e| unsafe {
            // SAFETY: owner thread; list items are transfer-full refs.
            let list = sys::frida_device_enumerate_processes_sync(d.get(), ptr::null_mut(), c, e);
            if list.is_null() {
                return Vec::new();
            }
            let n = sys::frida_process_list_size(list);
            let v = (0..n)
                .map(|i| {
                    let p = sys::frida_process_list_get(list, i);
                    let info = process_info(p);
                    sys::g_object_unref(p.cast());
                    info
                })
                .collect();
            sys::g_object_unref(list.cast());
            v
        })
    }

    pub(crate) fn get_process_by_pid(&self, pid: u32, cancel: &Cancel) -> FfiResult<ProcessInfo> {
        let d = self.raw;
        call(&self.rt, cancel, move |c, e| unsafe {
            // SAFETY: owner thread.
            let p = sys::frida_device_get_process_by_pid_sync(d.get(), pid, ptr::null_mut(), c, e);
            if p.is_null() {
                return None;
            }
            let info = process_info(p);
            sys::g_object_unref(p.cast());
            Some(info)
        })?
        .ok_or(FfiError::Frida {
            code: -1,
            message: format!("process {pid} not found"),
        })
    }

    /// Spawn `program` suspended. `argv` is the full vector (including argv[0]);
    /// `None` keeps frida's default.
    pub(crate) fn spawn(
        &self,
        program: &str,
        argv: Option<&[String]>,
        cancel: &Cancel,
    ) -> FfiResult<u32> {
        let program = cstring("program", program)?;
        let argv = argv
            .map(|a| {
                a.iter()
                    .map(|s| cstring("argv", s))
                    .collect::<FfiResult<Vec<_>>>()
            })
            .transpose()?;
        let len = argv
            .as_ref()
            .map(|a| i32::try_from(a.len()))
            .transpose()
            .map_err(|_| FfiError::InvalidArgument("argv too long".into()))?;
        let d = self.raw;
        call(&self.rt, cancel, move |c, e| unsafe {
            // SAFETY: owner thread; set_argv copies the strings.
            let o = sys::frida_spawn_options_new();
            if let (Some(a), Some(n)) = (&argv, len) {
                let mut ptrs: Vec<*mut c_char> = a.iter().map(|s| s.as_ptr().cast_mut()).collect();
                ptrs.push(ptr::null_mut());
                sys::frida_spawn_options_set_argv(o, ptrs.as_mut_ptr(), n);
            }
            let pid = sys::frida_device_spawn_sync(d.get(), program.as_ptr(), o, c, e);
            sys::g_object_unref(o.cast());
            pid
        })
    }

    pub(crate) fn resume(&self, pid: u32, cancel: &Cancel) -> FfiResult<()> {
        let d = self.raw;
        // SAFETY: owner thread.
        call(&self.rt, cancel, move |c, e| unsafe {
            sys::frida_device_resume_sync(d.get(), pid, c, e)
        })
    }

    pub(crate) fn attach(&self, pid: u32, cancel: &Cancel) -> FfiResult<Session> {
        let d = self.raw;
        let (tx, rx) = mpsc::channel();
        let (raw, handler) = call(&self.rt, cancel, move |c, e| unsafe {
            // SAFETY: owner thread; handler matches `detached`'s signature.
            let s = sys::frida_device_attach_sync(d.get(), pid, ptr::null_mut(), c, e);
            if s.is_null() {
                return (Raw(s), 0);
            }
            let h = connect(s.cast(), c"detached", on_detached as *const (), tx);
            (Raw(s), h)
        })?;
        Ok(Session {
            raw,
            handler,
            detached: rx,
            rt: Arc::clone(&self.rt),
        })
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        release_object(&self.rt, self.raw, None);
    }
}

// ---------------------------------------------------------------------------
// Session

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DetachedEvent {
    /// Frida's `FridaSessionDetachReason` nick (e.g. `application-requested`).
    pub reason: String,
    pub crashed: bool,
}

unsafe extern "C" fn on_detached(
    _session: *mut sys::FridaSession,
    reason: sys::FridaSessionDetachReason,
    crash: *mut sys::FridaCrash,
    data: *mut c_void,
) {
    // SAFETY: data is the Sender boxed by `connect`; reason is a valid enum.
    let tx = unsafe { &*data.cast::<Sender<DetachedEvent>>() };
    let reason = unsafe { enum_nick(sys::frida_session_detach_reason_get_type(), reason as i32) };
    let _ = tx.send(DetachedEvent {
        reason,
        crashed: !crash.is_null(),
    });
}

pub(crate) struct Session {
    raw: Raw<sys::FridaSession>,
    handler: u64,
    detached: Receiver<DetachedEvent>,
    rt: Arc<Runtime>,
}

impl Session {
    pub(crate) fn is_detached(&self) -> FfiResult<bool> {
        let s = self.raw;
        // SAFETY: owner thread.
        self.rt
            .run(move || unsafe { sys::frida_session_is_detached(s.get()) != 0 })
    }

    pub(crate) fn detached_events(&self) -> &Receiver<DetachedEvent> {
        &self.detached
    }

    pub(crate) fn create_script(
        &self,
        name: Option<&str>,
        source: &str,
        cancel: &Cancel,
    ) -> FfiResult<Script> {
        let name = name.map(|n| cstring("script name", n)).transpose()?;
        let source = cstring("script source", source)?;
        let s = self.raw;
        let (tx, rx) = mpsc::channel();
        let (raw, handler) = call(&self.rt, cancel, move |c, e| unsafe {
            // SAFETY: owner thread; handler matches `message`'s signature.
            let o = sys::frida_script_options_new();
            if let Some(n) = &name {
                sys::frida_script_options_set_name(o, n.as_ptr());
            }
            let sc = sys::frida_session_create_script_sync(s.get(), source.as_ptr(), o, c, e);
            sys::g_object_unref(o.cast());
            if sc.is_null() {
                return (Raw(sc), 0);
            }
            let h = connect(sc.cast(), c"message", on_message as *const (), tx);
            (Raw(sc), h)
        })?;
        Ok(Script {
            raw,
            handler,
            messages: rx,
            rt: Arc::clone(&self.rt),
        })
    }

    pub(crate) fn detach(&self, cancel: &Cancel) -> FfiResult<()> {
        let s = self.raw;
        // SAFETY: owner thread.
        call(&self.rt, cancel, move |c, e| unsafe {
            sys::frida_session_detach_sync(s.get(), c, e)
        })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        release_object(&self.rt, self.raw, Some(self.handler));
    }
}

// ---------------------------------------------------------------------------
// Script

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScriptMessage {
    /// The raw JSON message text exactly as frida-core delivered it.
    pub json: String,
    /// The optional binary payload (`send(msg, data)`).
    pub data: Option<Vec<u8>>,
}

unsafe extern "C" fn on_message(
    _script: *mut sys::FridaScript,
    message: *const c_char,
    bytes: *mut sys::GBytes,
    data: *mut c_void,
) {
    // SAFETY: data is the Sender boxed by `connect`; bytes is null or live.
    let tx = unsafe { &*data.cast::<Sender<ScriptMessage>>() };
    let payload = (!bytes.is_null()).then(|| unsafe {
        let mut n: sys::gsize = 0;
        let p = sys::g_bytes_get_data(bytes, &mut n);
        if p.is_null() || n == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(p.cast::<u8>(), n as usize).to_vec()
        }
    });
    let _ = tx.send(ScriptMessage {
        json: cstr(message),
        data: payload,
    });
}

pub(crate) struct Script {
    raw: Raw<sys::FridaScript>,
    handler: u64,
    messages: Receiver<ScriptMessage>,
    rt: Arc<Runtime>,
}

impl Script {
    pub(crate) fn load(&self, cancel: &Cancel) -> FfiResult<()> {
        let s = self.raw;
        // SAFETY: owner thread.
        call(&self.rt, cancel, move |c, e| unsafe {
            sys::frida_script_load_sync(s.get(), c, e)
        })
    }

    pub(crate) fn unload(&self, cancel: &Cancel) -> FfiResult<()> {
        let s = self.raw;
        // SAFETY: owner thread.
        call(&self.rt, cancel, move |c, e| unsafe {
            sys::frida_script_unload_sync(s.get(), c, e)
        })
    }

    pub(crate) fn is_destroyed(&self) -> FfiResult<bool> {
        let s = self.raw;
        // SAFETY: owner thread.
        self.rt
            .run(move || unsafe { sys::frida_script_is_destroyed(s.get()) != 0 })
    }

    pub(crate) fn messages(&self) -> &Receiver<ScriptMessage> {
        &self.messages
    }
}

impl Drop for Script {
    fn drop(&mut self) {
        release_object(&self.rt, self.raw, Some(self.handler));
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn invalid_arguments_are_rejected_before_crossing() {
        assert!(matches!(
            cstring("x", "a\0b"),
            Err(FfiError::InvalidArgument(_))
        ));
    }

    #[test]
    fn cancelled_call_reports_cancelled() {
        let rt = Runtime::start().unwrap();
        let dm = DeviceManager::new(&rt).unwrap();
        let c = rt.cancellable().unwrap();
        c.cancel();
        // A cancelled lookup of a nonexistent device must fail as Cancelled.
        let r = dm.get_device_by_id("rea-no-such-device", 5_000, &c);
        assert_eq!(r.err(), Some(FfiError::Cancelled));
    }

    fn build_target(dir: &std::path::Path) -> PathBuf {
        let src = dir.join("t.c");
        std::fs::write(
            &src,
            "#include <unistd.h>\nint main(void){for(int i=0;i<5;i++)usleep(100000);return 0;}\n",
        )
        .unwrap();
        let out = dir.join("t");
        let st = std::process::Command::new("cc")
            .arg(&src)
            .arg("-o")
            .arg(&out)
            .status()
            .unwrap();
        assert!(st.success());
        out
    }

    fn alive(pid: u32) -> bool {
        // SAFETY: signal 0 only probes existence.
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }

    #[test]
    #[ignore = "live: requires a local frida device"]
    fn live_local_device_lifecycle() {
        let rt = Runtime::start().unwrap();
        let c = rt.cancellable().unwrap();
        let dm = DeviceManager::new(&rt).unwrap();

        let devices = dm.enumerate_devices(&c).unwrap();
        let described = devices
            .iter()
            .map(|d| d.describe().unwrap())
            .collect::<Vec<_>>();
        assert!(
            described
                .iter()
                .any(|(id, _, t)| id == "local" && t == "local"),
            "{described:?}"
        );
        let dev = dm.get_device_by_id("local", 1_000, &c).unwrap();
        assert!(!dev.enumerate_processes(&c).unwrap().is_empty());

        let dir = tempfile::tempdir().unwrap();
        let target = build_target(dir.path());
        let program = target.to_string_lossy().into_owned();
        let pid = dev
            .spawn(&program, Some(&[program.clone(), "x".into()]), &c)
            .unwrap();
        assert_eq!(dev.get_process_by_pid(pid, &c).unwrap().pid, pid);

        let session = dev.attach(pid, &c).unwrap();
        assert!(!session.is_detached().unwrap());
        let script = session
            .create_script(
                Some("rea-ffi-test"),
                "send({kind:'json', n:42}); send({kind:'bin'}, new Uint8Array([1,2,3,255]).buffer);",
                &c,
            )
            .unwrap();
        script.load(&c).unwrap();
        let wait = Duration::from_secs(5);
        let m1 = script.messages().recv_timeout(wait).unwrap();
        let m2 = script.messages().recv_timeout(wait).unwrap();
        let v1: serde_json::Value = serde_json::from_str(&m1.json).unwrap();
        assert_eq!(v1["type"], "send");
        assert_eq!(v1["payload"]["n"], 42);
        assert_eq!(m1.data, None);
        let v2: serde_json::Value = serde_json::from_str(&m2.json).unwrap();
        assert_eq!(v2["payload"]["kind"], "bin");
        assert_eq!(m2.data.as_deref(), Some(&[1u8, 2, 3, 255][..]));

        script.unload(&c).unwrap();
        assert!(script.is_destroyed().unwrap());
        session.detach(&c).unwrap();
        assert!(session.is_detached().unwrap());
        let ev = session.detached_events().recv_timeout(wait).unwrap();
        assert_eq!(ev.reason, "application-requested");
        drop(script);
        drop(session);

        dev.resume(pid, &c).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(!alive(pid), "child {pid} did not exit after resume");
        assert!(dev.get_process_by_pid(pid, &c).is_err());
    }
}
