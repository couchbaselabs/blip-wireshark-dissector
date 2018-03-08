// Experimental dissector for BLIP (https://github.com/couchbaselabs/BLIP-Cpp)
//
// License: Apache2
//
// BLIP protocol spec: https://github.com/couchbaselabs/BLIP-Cpp/blob/a33262740787bbdfb17eef6d8a6ab4a5e18fe089/docs/BLIP%20Protocol.md
//

#include "config.h"

#include <epan/packet.h>
#include <epan/tvbparse.h>
#include <wsutil/wsjsmn.h>

#include <wsutil/str_util.h>
#include <wsutil/unicode-utils.h>

#include <wiretap/wtap.h>
#include <printf.h>

#include "packet-http.h"


// Cribbed from https://stackoverflow.com/questions/111928/is-there-a-printf-converter-to-print-in-binary-format
#define PRINTF_BINARY_PATTERN_INT8 "%c%c%c%c%c%c%c%c"
#define PRINTF_BYTE_TO_BINARY_INT8(i)    \
    (((i) & 0x80ll) ? '1' : '0'), \
    (((i) & 0x40ll) ? '1' : '0'), \
    (((i) & 0x20ll) ? '1' : '0'), \
    (((i) & 0x10ll) ? '1' : '0'), \
    (((i) & 0x08ll) ? '1' : '0'), \
    (((i) & 0x04ll) ? '1' : '0'), \
    (((i) & 0x02ll) ? '1' : '0'), \
    (((i) & 0x01ll) ? '1' : '0')

#define PRINTF_BINARY_PATTERN_INT16 \
    PRINTF_BINARY_PATTERN_INT8              PRINTF_BINARY_PATTERN_INT8
#define PRINTF_BYTE_TO_BINARY_INT16(i) \
    PRINTF_BYTE_TO_BINARY_INT8((i) >> 8),   PRINTF_BYTE_TO_BINARY_INT8(i)
#define PRINTF_BINARY_PATTERN_INT32 \
    PRINTF_BINARY_PATTERN_INT16             PRINTF_BINARY_PATTERN_INT16
#define PRINTF_BYTE_TO_BINARY_INT32(i) \
    PRINTF_BYTE_TO_BINARY_INT16((i) >> 16), PRINTF_BYTE_TO_BINARY_INT16(i)
#define PRINTF_BINARY_PATTERN_INT64    \
    PRINTF_BINARY_PATTERN_INT32             PRINTF_BINARY_PATTERN_INT32
#define PRINTF_BYTE_TO_BINARY_INT64(i) \
    PRINTF_BYTE_TO_BINARY_INT32((i) >> 32), PRINTF_BYTE_TO_BINARY_INT32(i)
/* --- end macros --- */

gboolean is_compressed(guint64);

static dissector_handle_t blip_handle;

static int proto_blip = -1;

static int hf_blip_message_number = -1;
static int hf_blip_frame_flags = -1;
static int hf_blip_properties_length = -1;
static int hf_blip_properties = -1;
static int hf_blip_message_body = -1;

static gint ett_blip = -1;


static int
dissect_blip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    proto_tree *blip_tree;
    gint        offset = 0;

    /* Set the protcol column to say BLIP */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLIP");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    // ------------------------------------- BLIP tree -----------------------------------------------------------------


    /* Add a subtree to dissection.  See WSDG 9.2.2. Dissecting the details of the protocol  */
    proto_item *blip_item = proto_tree_add_item(tree, proto_blip, tvb, offset, -1, ENC_NA);

    blip_tree = proto_item_add_subtree(blip_item, ett_blip);


    // ------------------------ BLIP Frame Header: Message Number VarInt -----------------------------------------------

    // This gets the message number as a var int in order to find out how much to bump
    // the offset for the next proto_tree item
    guint64 value_message_num;
    guint varint_message_num_length = tvb_get_varint(
            tvb,
            offset,
            FT_VARINT_MAX_LEN,
            &value_message_num,
            ENC_VARINT_PROTOBUF);

    printf("BLIP message number: %" G_GUINT64_FORMAT "\n", value_message_num);

    proto_tree_add_item(blip_tree, hf_blip_message_number, tvb, offset, varint_message_num_length, ENC_VARINT_PROTOBUF);

    offset += varint_message_num_length;
    printf("new offset: %d\n", offset);


    // ------------------------ BLIP Frame Header: Frame Flags VarInt --------------------------------------------------

    // This gets the message number as a var int in order to find out how much to bump
    // the offset for the next proto_tree item
    guint64 value_frame_flags;
    guint varint_frame_flags_length = tvb_get_varint(
            tvb,
            offset,
            FT_VARINT_MAX_LEN,
            &value_frame_flags,
            ENC_VARINT_PROTOBUF);

    printf("BLIP frame flags: %" G_GUINT64_FORMAT "\n", value_frame_flags);

    proto_tree_add_item(blip_tree, hf_blip_frame_flags, tvb, offset, varint_frame_flags_length, ENC_VARINT_PROTOBUF);

    offset += varint_frame_flags_length;
    printf("new offset: %d\n", offset);

    printf("Frame flags "
                   PRINTF_BINARY_PATTERN_INT8 "\n",
           PRINTF_BYTE_TO_BINARY_INT8(value_frame_flags));


    // If it's compressed, don't try to do any more decoding
    // TODO: How can this indicate it's compressed in the UI?  Can it somehow call proto_tree_add_item() and tell
    // TODO: tell it to read the varint, and then run a bitmask on it?  Or is there another more direct way to
    // TODO: add an empty item and then explicitly set it.
    if (is_compressed(value_frame_flags) == TRUE) {
        col_set_str(pinfo->cinfo, COL_INFO, "Compressed -- cannot decode further");
        return tvb_captured_length(tvb);
    }

    // If it's an ACK message, handle that separately, since there are no properties etc.
//    if is_ack(value_frame_flags) {
//        return handle_ack(tvb, pinfo, blip_tree, offset, value_frame_flags)
//    }


    // TODO: if this flag is set:
    // TODO:    MoreComing= 0x40  // 0100 0000
    // TODO: it should issue warnings that subsequent packets in this conversation will be broken, since it currently
    // TODO: doesn't handle messages split among multiple frames

    // TODO: if this flag is set:
    // TODO:    Compressed= 0x08  // 0000 1000
    // TODO: it should not try to decode the body into json (or are properties compressed too!?)

    // ------------------------ BLIP Frame Header: Properties Length VarInt --------------------------------------------------

    // WARNING: this only works because this code assumes that ALL MESSAGES FIT INTO ONE FRAME, which is absolutely not true.
    // In other words, as soon as there is a message that spans two frames, this code will break.

    guint64 value_properties_length;
    guint value_properties_length_varint_length = tvb_get_varint(
            tvb,
            offset,
            FT_VARINT_MAX_LEN,
            &value_properties_length,
            ENC_VARINT_PROTOBUF);

    printf("BLIP properties length: %" G_GUINT64_FORMAT "\n", value_properties_length);

    proto_tree_add_item(blip_tree, hf_blip_properties_length, tvb, offset, value_properties_length_varint_length, ENC_VARINT_PROTOBUF);

    offset += value_properties_length_varint_length;
    printf("new offset: %d\n", offset);

    // ------------------------ BLIP Frame: Properties --------------------------------------------------

    // WARNING: this only works because this code assumes that ALL MESSAGES FIT INTO ONE FRAME, which is absolutely not true.
    // In other words, as soon as there is a message that spans two frames, this code will break.

    // At this point, the length of the properties is known and is stored in value_properties_length.
    // This reads the entire properties out of the tvb and into a buffer (buf).
    guint8* buf = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, (gint) value_properties_length, ENC_UTF_8);

    // "Profile\0subChanges\0continuous\0true\0foo\0bar" -> "Profile:subChanges:continuous:true:foo:bar"
    // Iterate over buf and change all the \0 null characters to ':', since otherwise trying to set a header
    // field to this buffer via proto_tree_add_item() will end up only printing it up to the first null character,
    // for example "Profile", even though there are many more properties that follow.
    for (int i = 0; i < (int) value_properties_length; i++) {
        if (i < (int) (value_properties_length - 1)) {
            if (buf[i] == '\0') {  // TODO: I don't even know if this is actually a safe assumption in a UTF-8 encoded string
                buf[i] = ':';
            }
        }
    }

    // Since proto_tree_add_item() requires a tvbuff, convert the guint8* buf into a tvbuff.  tvb_new_child_real_data()
    // is used so that it will be free'd at the same time that the parent tvb is freed.
    // See WSDG 9.3. How to handle transformed data.
    tvbuff_t* tvb_child = tvb_new_child_real_data(tvb, buf, (guint) value_properties_length, (guint) value_properties_length);

    // Add this to the tree from the tvb_child tvbuff, and use offset=0 since it that buffer only
    // contains the properties, which are now delimited by ':' in between each property.
    // TODO: Since it's a child tvbuff, clicking this in the wireshark UI doesn't highlight the correct
    // TODO: subset of the raw data.  That would be a nice-to-have
    proto_tree_add_item(blip_tree, hf_blip_properties, tvb_child, 0, (guint) value_properties_length, ENC_UTF_8);

    // Bump the offset by the length of the properties
    offset += value_properties_length;
    printf("new offset: %d\n", offset);


    // ------------------------ BLIP Frame: Message Body --------------------------------------------------

    // WS_DLL_PUBLIC gint tvb_reported_length_remaining(const tvbuff_t *tvb, const gint offset);
    gint reported_length_remaining = tvb_reported_length_remaining(tvb, offset);

    // TODO: in certain conditions, should ignore the checksum at the end

    proto_tree_add_item(blip_tree, hf_blip_message_body, tvb, offset, reported_length_remaining, ENC_UTF_8);

    offset += reported_length_remaining;
    printf("new offset: %d\n", offset);

    // -------------------------------------------- Etc ----------------------------------------------------------------

    // Stop compiler from complaining about unused function params
    if (pinfo || data) {}

    return tvb_captured_length(tvb);
}

gboolean
is_compressed(guint64 value_frame_flags)
{
    // Note, even though this is a 64-bit int, only the least significant byte has meaningful information,
    // since frame flags all fit into one byte at the time this code was written.

    if ((0x08ll & value_frame_flags) > 0) {
        return TRUE;
    }

    return FALSE;


}

void
proto_register_blip(void)
{

    static hf_register_info hf[] = {
            { &hf_blip_message_number,
                    { "BLIP Message Number", "blip.messagenum",
                            FT_UINT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_frame_flags,
                    { "BLIP Frame Flags", "blip.frameflags",
                            FT_UINT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_properties_length,
                    { "BLIP Properties Length", "blip.propslength",
                            FT_UINT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_properties,
                    { "BLIP Properties", "blip.props",
                            FT_STRING, STR_UNICODE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_message_body,
                    { "BLIP Message Body", "blip.messagebody",
                            FT_STRING, STR_UNICODE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
            &ett_blip
    };

    proto_blip = proto_register_protocol("BLIP Couchbase Mobile", "BLIP", "blip");

    proto_register_field_array(proto_blip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    blip_handle = register_dissector("blip", dissect_blip, proto_blip);

}

void
proto_reg_handoff_blip(void)
{

    // Register the blip dissector as a subprotocol dissector of "ws.protocol",
    // matching any packets with a Web-Sec-Protocol header of "BLIP_3+CBMobile_2".
    //
    // See https://github.com/couchbase/sync_gateway/issues/3356#issuecomment-370958321 for
    // more notes on how the websocket dissector routes packets down to subprotocol handlers.

    ftenum_t type;
    dissector_table_t table = find_dissector_table("ws.protocol");
    if (table) {
        //printf("table is not nil");
    }
    type = get_dissector_table_selector_type("ws.protocol");
    if (type == FT_STRING) {
        // printf("is FT_STRING");
        dissector_add_string("ws.protocol", "BLIP_3+CBMobile_2", blip_handle);
    } else {
        // printf("not FT_STRING");
    }


}
