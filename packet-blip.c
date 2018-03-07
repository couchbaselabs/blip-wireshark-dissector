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


static dissector_handle_t blip_handle;

static int proto_blip = -1;


static int
dissect_blip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    /* Set the protcol column to say BLIP */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLIP");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* Add a subtree to dissection.  See 9.2.2. Dissecting the details of the protocol of WSDG */

    // proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint encoding)

    proto_item *ti = proto_tree_add_item(tree, proto_blip, tvb, 0, -1, ENC_NA);
    printf("ti: %p", ti); // appease compiler

    guint64 value;
    guint varint_length = tvb_get_varint(
            tvb,
            0,
            FT_VARINT_MAX_LEN,
            &value,
            ENC_VARINT_PROTOBUF);
    printf("My value: %" G_GUINT64_FORMAT "\n", value);
    printf("varint len: %d\n", varint_length);

    // Stop compiler from complaitning about unused variables
    if (pinfo || tree || data) {

    }


    return tvb_captured_length(tvb);
}



void
proto_register_blip(void)
{

    proto_blip = proto_register_protocol("BLIP Couchbase Mobile", "BLIP", "blip");

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
        printf("table is not nil");
    }
    type = get_dissector_table_selector_type("ws.protocol");
    if (type == FT_STRING) {
        printf("is FT_STRING");
        dissector_add_string("ws.protocol", "BLIP_3+CBMobile_2", blip_handle);
    } else {
        printf("not FT_STRING");
    }


}
