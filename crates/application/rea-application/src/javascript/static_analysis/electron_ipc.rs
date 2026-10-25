//! Electron IPC naming and handler classification.

use crate::javascript::ast::{AstContext, Field, Node};

use super::electron_values::{
    bounded_expression, electron_static_value, handler_kind, member_path,
};
use crate::javascript::contracts::static_analysis::StaticValue;
use crate::javascript::semantic::value_types::{JsString, Primitive};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcMode {
    Send,
    Invoke,
    Listen,
    Handle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpcDescriptor {
    pub side: &'static str,
    pub operation: &'static str,
    pub mode: IpcMode,
}

pub fn ipc_descriptor(path: &[String]) -> Option<IpcDescriptor> {
    if path.len() != 2 {
        return None;
    }
    let (object, operation) = (path[0].as_str(), path[1].as_str());
    let (side, mode, operation) = match (object, operation) {
        ("ipcRenderer", "send") => ("renderer", IpcMode::Send, "send"),
        ("ipcRenderer", "sendSync") => ("renderer", IpcMode::Send, "send-sync"),
        ("ipcRenderer", "invoke") => ("renderer", IpcMode::Invoke, "invoke"),
        ("ipcRenderer", "postMessage") => ("renderer", IpcMode::Send, "post-message"),
        ("ipcRenderer", "sendToHost") => ("renderer", IpcMode::Send, "send-to-host"),
        ("ipcRenderer", "addListener" | "on") => ("renderer", IpcMode::Listen, "on"),
        ("ipcRenderer", "once") => ("renderer", IpcMode::Listen, "once"),
        ("ipcMain", "addListener" | "on") => ("main", IpcMode::Listen, "on"),
        ("ipcMain", "once") => ("main", IpcMode::Listen, "once"),
        ("ipcMain", "handle") => ("main", IpcMode::Handle, "handle"),
        ("ipcMain", "handleOnce") => ("main", IpcMode::Handle, "handle-once"),
        _ => return None,
    };
    Some(IpcDescriptor {
        side,
        operation,
        mode,
    })
}

pub fn channel_value<'a>(
    context: &AstContext<'a>,
    call: Node<'a>,
) -> (Option<JsString>, Option<String>, StaticValue) {
    let channel = call
        .field_list(context.source(), Field::Arguments)
        .into_iter()
        .next()
        .flatten();
    let value = electron_static_value(context, channel);
    let literal = match (&value.value, value.status.as_str()) {
        (Primitive::String(channel), "literal") => Some(channel.clone()),
        _ => None,
    };
    let expression = literal
        .is_none()
        .then(|| bounded_expression(context, channel));
    (literal, expression, value)
}

pub fn call_handler_kind(context: &AstContext<'_>, call: Node<'_>) -> &'static str {
    call.field_list(context.source(), Field::Arguments)
        .get(1)
        .copied()
        .flatten()
        .map(|node| handler_kind(Some(node)))
        .unwrap_or("missing")
}

pub fn descriptor_for_call(context: &AstContext<'_>, call: Node<'_>) -> Option<IpcDescriptor> {
    let callee = call.field(context.source(), Field::Callee)?;
    let path = member_path(context, callee)?;
    ipc_descriptor(&path)
}

#[cfg(test)]
mod tests {
    use super::{IpcMode, ipc_descriptor};

    #[test]
    fn recognizes_renderer_and_main_operations() {
        assert_eq!(
            ipc_descriptor(&["ipcRenderer".into(), "invoke".into()]).map(|it| it.mode),
            Some(IpcMode::Invoke)
        );
        assert_eq!(
            ipc_descriptor(&["ipcRenderer".into(), "on".into()]).map(|it| it.operation),
            Some("on")
        );
        assert_eq!(
            ipc_descriptor(&["ipcMain".into(), "handleOnce".into()]).map(|it| it.operation),
            Some("handle-once")
        );
        assert_eq!(
            ipc_descriptor(&["ipcRenderer".into(), "send".into(), "extra".into()]),
            None
        );
    }
}
