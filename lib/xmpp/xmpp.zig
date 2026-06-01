pub const jid = @import("jid.zig");
pub const stanza = @import("stanza.zig");

pub const Jid = jid.Jid;
pub const Stanza = stanza.Stanza;
pub const StanzaType = stanza.StanzaType;
pub const Message = stanza.Message;
pub const MessageType = stanza.MessageType;
pub const Presence = stanza.Presence;
pub const PresenceType = stanza.PresenceType;
pub const PresenceShow = stanza.PresenceShow;
pub const Iq = stanza.Iq;
pub const IqType = stanza.IqType;
pub const StanzaHeader = stanza.StanzaHeader;

pub const serializeMessage = stanza.serializeMessage;
pub const serializePresence = stanza.serializePresence;
pub const serializeIq = stanza.serializeIq;

test {
    _ = jid;
    _ = stanza;
}
