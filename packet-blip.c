/* Originally adapted from packet-json.c
 * Routines for JSON dissection
 * References:
 *     RFC 4627: http://tools.ietf.org/html/rfc4627
 *     Website:  http://json.org/
 *
 * Copyright 2010, Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

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


static dissector_handle_t blip_handle;

static int proto_blip = -1;

static int hf_blip_message_number = -1;
static int hf_blip_frame_flags = -1;

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


    /* Add a subtree to dissection.  See 9.2.2. Dissecting the details of the protocol of WSDG */
    proto_item *blip_item = proto_tree_add_item(tree, proto_blip, tvb, offset, -1, ENC_NA);

    blip_tree = proto_item_add_subtree(blip_item, ett_blip);


    // ------------------------ BLIP Message Number VarInt frame header ------------------------------------------------

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

    // TODO: It might be worth testing to make sure ENC_VARINT_PROTOBUF is actually working here
    // TODO: by having message numbers larger that don't fit in 16-bits, and see if it renders properly after this fix.
    // TODO: I'm not sure if this should be (ENC_BIG_ENDIAN | ENC_VARINT_PROTOBUF) or just ENC_VARINT_PROTOBUF.
    proto_tree_add_item(blip_tree, hf_blip_message_number, tvb, offset, varint_message_num_length, ENC_VARINT_PROTOBUF);

    offset += varint_message_num_length;
    printf("new offset: %d\n", offset);


    // ------------------------ BLIP Message Number VarInt frame flags ------------------------------------------------

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


    // TODO: if this flag is set:
    // TODO:    MoreComing= 0x40  // 0100 0000
    // TODO: it should issue warnings that subsequent packets in this conversation will be broken, since it currently
    // TODO: doesn't handle messages split among multiple frames


    // -------------------------------------------- Etc ----------------------------------------------------------------

    // Stop compiler from complaining about unused variables
    if (pinfo || tree || data) {

    }

    return tvb_captured_length(tvb);
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
