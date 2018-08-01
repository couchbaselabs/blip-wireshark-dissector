// Experimental dissector for BLIP (https://github.com/couchbaselabs/BLIP-Cpp)
//
// License: Apache2
//
// BLIP protocol spec: https://github.com/couchbaselabs/BLIP-Cpp/blob/a33262740787bbdfb17eef6d8a6ab4a5e18fe089/docs/BLIP%20Protocol.md
//

#include "config.h"

#include <epan/packet.h>
#include <epan/tvbparse.h>
#include <wsutil/wsjson.h>

#include <wsutil/str_util.h>
#include <wsutil/unicode-utils.h>
#include <epan/conversation.h>

#include <wiretap/wtap.h>
#include <stdio.h>
#include <zlib.h>

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

#define BLIP_BODY_CHECKSUM_SIZE 4

// blip_conversation_entry_t is metadata that the blip dissector associates w/ each wireshark conversation
typedef struct {

    // Keep track of the largest frame number seen.  This is useful for determining whether
    // this is the first frame in a request message or not.

    // key: msgtype:srcport:messagenumber -> value: frame number for the _first_ frame in this request message
    // Example: "MSG:23243:56" -> 12
    // which means: "the first frame for blip message number 56, originating from source port 23243, and for message type = MSG
    //               ... occurred in wireshark packet #12"
    wmem_map_t *blip_requests;

} blip_conversation_entry_t;


// Forward declarations
static gboolean is_compressed(guint64);
static gboolean is_ack_message(guint64);
static GString* get_message_type(guint64);
static gboolean is_first_frame_in_msg(
        blip_conversation_entry_t *blip_conversation_entry,
        packet_info *pinfo,
        guint64 value_frame_flags,
        guint64 value_message_num
);
static int handle_ack_message(tvbuff_t*, packet_info*, proto_tree*, gint, guint64);
static tvbuff_t* decompress(packet_info*, tvbuff_t*, z_stream*, gint, gint);
static z_stream* get_decompress_stream(guint64);
static dissector_handle_t blip_handle;

// File level variables
static int proto_blip = -1;
static int hf_blip_message_number = -1;
static int hf_blip_frame_flags = -1;
static int hf_blip_properties_length = -1;
static int hf_blip_properties = -1;
static int hf_blip_message_body = -1;
static int hf_blip_ack_size = -1;
static int hf_blip_checksum = -1;
static gint ett_blip = -1;
static z_stream decompress_stream_up;
static z_stream decompress_stream_down;
static Bytef decompress_buffer[16384];

static int
dissect_blip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    proto_tree *blip_tree;
    gint        offset = 0;

    /* Set the protcol column to say BLIP */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLIP");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    
    // ------------------------------------- Setup BLIP tree -----------------------------------------------------------


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

    guint64 masked = value_frame_flags & ~0x07;
    printf("BLIP frame flags: %" G_GUINT64_FORMAT "\n", masked);

    proto_tree_add_uint(blip_tree, hf_blip_frame_flags, tvb, offset, varint_frame_flags_length, (guint8)masked);

    offset += varint_frame_flags_length;
    printf("new offset: %d\n", offset);

    printf("Frame flags "
                   PRINTF_BINARY_PATTERN_INT8 "\n",
           PRINTF_BYTE_TO_BINARY_INT8(value_frame_flags));

    GString *msg_type = get_message_type(value_frame_flags);
    g_string_append_printf(msg_type, "#%" G_GUINT64_FORMAT, value_message_num);
    col_add_str(pinfo->cinfo, COL_INFO, msg_type->str);
    g_string_free(msg_type, TRUE);
    
    // If it's an ACK message, handle that separately, since there are no properties etc.
    if (is_ack_message(value_frame_flags) == TRUE) {
        return handle_ack_message(tvb, pinfo, blip_tree, offset, value_frame_flags);
    }


    // ------------------------------------- Conversation Tracking -----------------------------------------------------

    // Create a new conversation if needed and associate the blip_conversation_entry_t with it
    // Adapted from sample code in https://raw.githubusercontent.com/wireshark/wireshark/master/doc/README.dissector
    conversation_t *conversation;
    conversation = find_or_create_conversation(pinfo);
    blip_conversation_entry_t *conversation_entry_ptr = (blip_conversation_entry_t*)conversation_get_proto_data(conversation, proto_blip);
    if (conversation_entry_ptr == NULL) {

        // create a new blip_conversation_entry_t
        conversation_entry_ptr = wmem_alloc(wmem_file_scope(), sizeof(blip_conversation_entry_t));

        // create a new hash map and save a reference in blip_conversation_entry_t
        conversation_entry_ptr->blip_requests = wmem_map_new(wmem_file_scope(), g_str_hash, g_str_equal);

    }

    // Is this the first frame in a blip message with multiple frames?
    gboolean first_frame_in_msg = is_first_frame_in_msg(
            conversation_entry_ptr,
            pinfo,
            value_frame_flags,
            value_message_num
    );

    // Update the conversation w/ the latest version of the blip_conversation_entry_t
    conversation_add_proto_data(conversation, proto_blip, (void *)conversation_entry_ptr);
    
    tvbuff_t* tvb_to_use = tvb;
    gboolean compressed = is_compressed(value_frame_flags);
    if(compressed) {
        // TODO:  Need to cache these, since this is very much not replayable and will result in
        // unpredictable things happening.  The frames *must* be processed in order for this to give
        // the correct result, but scrolling wireshark, etc, results in this being called multiple times
        // for the same frames in probably randomish order
        tvb_to_use = decompress(pinfo, tvb, get_decompress_stream(value_frame_flags), offset, tvb_reported_length_remaining(tvb, offset) - BLIP_BODY_CHECKSUM_SIZE);
        if(!tvb_to_use) {
            proto_tree_add_string(blip_tree, hf_blip_message_body, tvb, offset, tvb_reported_length_remaining(tvb, offset), "<Error decompressing message>");
            return tvb_reported_length(tvb);
        }
        
        offset = 0;
    }

    // Is this the first frame in a message?
    if (first_frame_in_msg == TRUE) {

        // ------------------------ BLIP Frame Header: Properties Length VarInt --------------------------------------------------

        // WARNING: this only works because this code assumes that ALL MESSAGES FIT INTO ONE FRAME, which is absolutely not true.
        // In other words, as soon as there is a message that spans two frames, this code will break.

        guint64 value_properties_length;
        guint value_properties_length_varint_length = tvb_get_varint(
                tvb_to_use,
                offset,
                FT_VARINT_MAX_LEN,
                &value_properties_length,
                ENC_VARINT_PROTOBUF);

        printf("BLIP properties length: %" G_GUINT64_FORMAT "\n", value_properties_length);

        proto_tree_add_item(blip_tree, hf_blip_properties_length, tvb_to_use, offset, value_properties_length_varint_length, ENC_VARINT_PROTOBUF);

        offset += value_properties_length_varint_length;
        printf("new offset: %d\n", offset);

        // ------------------------ BLIP Frame: Properties --------------------------------------------------

        // WARNING: this only works because this code assumes that ALL MESSAGES FIT INTO ONE FRAME, which is absolutely not true.
        // In other words, as soon as there is a message that spans two frames, this code will break.

        // At this point, the length of the properties is known and is stored in value_properties_length.
        // This reads the entire properties out of the tvb and into a buffer (buf).
        guint8* buf = tvb_get_string_enc(wmem_packet_scope(), tvb_to_use, offset, (gint) value_properties_length, ENC_UTF_8);

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
        
        if(value_properties_length > 0) {
            proto_tree_add_string(blip_tree, hf_blip_properties, tvb_to_use, offset, (int)value_properties_length, (const char *)buf);
        }

        // Bump the offset by the length of the properties
        offset += (gint)value_properties_length;
        printf("new offset: %d\n", offset);


    }

    // ------------------------ BLIP Frame: Message Body --------------------------------------------------

    // WS_DLL_PUBLIC gint tvb_reported_length_remaining(const tvbuff_t *tvb, const gint offset);
    gint reported_length_remaining = tvb_reported_length_remaining(tvb_to_use, offset);

    // Don't read in the trailing checksum at the end
    if (!compressed && reported_length_remaining >= BLIP_BODY_CHECKSUM_SIZE) {
        reported_length_remaining -= BLIP_BODY_CHECKSUM_SIZE;
    }
    
    if(reported_length_remaining > 0) {
        proto_tree_add_item(blip_tree, hf_blip_message_body, tvb_to_use, offset, reported_length_remaining, ENC_UTF_8);
    }

    offset += reported_length_remaining;
    printf("new offset: %d\n", offset);
    
    proto_tree_add_item(blip_tree, hf_blip_checksum, tvb, tvb_reported_length(tvb) - BLIP_BODY_CHECKSUM_SIZE, BLIP_BODY_CHECKSUM_SIZE, ENC_BIG_ENDIAN);

    // -------------------------------------------- Etc ----------------------------------------------------------------

    // Stop compiler from complaining about unused function params
    if (pinfo || data) {}

    return tvb_captured_length(tvb);
}

static gboolean
is_compressed(guint64 value_frame_flags)
{
    // Note, even though this is a 64-bit int, only the least significant byte has meaningful information,
    // since frame flags all fit into one byte at the time this code was written.

    if ((0x08ll & value_frame_flags) == 0x08ll) {
        return TRUE;
    }

    return FALSE;

}

// MSG =    0x00
// RPY =    0x01
// ERR =    0x02
// ACKMSG = 0x04
// ACKRPY = 0x05
static GString*
get_message_type(guint64 value_frame_flags)
{

    // Mask out the least significant bits: 0000 0111
    guint64 type_mask_val = (0x07ll & value_frame_flags);

    // MSG
    if (type_mask_val == 0x00ll) {
        return g_string_new("MSG");
    }

    // RPY
    if (type_mask_val == 0x01ll) {
        return g_string_new("RPY");
    }

    // ERR
    if (type_mask_val == 0x02ll) {
        return g_string_new("ERR");
    }

    // ACKMSG
    if (type_mask_val == 0x04ll) {
        return g_string_new("ACKMSG");
    }

    // ACKRPY
    if (type_mask_val == 0x05ll) {
        return g_string_new("ACKRPY");
    }


    return g_string_new("???");

}


static gboolean
is_ack_message(guint64 value_frame_flags)
{
    // Note, even though this is a 64-bit int, only the least significant byte has meaningful information,
    // since frame flags all fit into one byte at the time this code was written.

    // Mask out the least significant bits: 0000 0111
    guint64 type_mask_val = (0x07ll & value_frame_flags);

    // ACKMSG
    if (type_mask_val == 0x04ll) {
        return TRUE;
    }

    // ACKRPY
    if (type_mask_val == 0x05ll) {
        return TRUE;
    }

    return FALSE;

}

static int
handle_ack_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *blip_tree, gint offset, guint64 value_frame_flags)
{

    // Appease compiler about unused variables
    if (pinfo || blip_tree || offset || value_frame_flags) {}

    // This gets the number of ack bytes received  as a var int in order to find out how much to bump
    // the offset for the next proto_tree item
    guint64 value_ack_size;
    guint varint_ack_size_length = tvb_get_varint(
            tvb,
            offset,
            FT_VARINT_MAX_LEN,
            &value_ack_size,
            ENC_VARINT_PROTOBUF);

    printf("BLIP ack size: %" G_GUINT64_FORMAT "\n", value_ack_size);

    proto_tree_add_item(blip_tree, hf_blip_ack_size, tvb, offset, varint_ack_size_length, ENC_VARINT_PROTOBUF);

    offset += varint_ack_size_length;
    printf("new offset: %d\n", offset);

    return tvb_captured_length(tvb);
}

// Finds out whether this is the first blip frame in the blip message (which can consist of a series of frames).
// If it is, updates the conversation_entry_ptr->blip_requests hash to record the pinfo->num (wireshark packet number)
static gboolean
is_first_frame_in_msg(blip_conversation_entry_t *conversation_entry_ptr, packet_info *pinfo, guint64 value_frame_flags, guint64 value_message_num) {

    gboolean first_frame_in_msg = TRUE;

    // Temporary pool for the lookup hash_key.  Will get duplicated on the file_scope() pool if needed to be
    // stored in the hashtable.
    wmem_allocator_t *pool;
    pool = wmem_allocator_new(WMEM_ALLOCATOR_SIMPLE);


    // Derive the hash key to use
    // msgtype:srcport:messagenum

    GString *msg_type = get_message_type(value_frame_flags);
    gchar *srcport = g_strdup_printf("%u", pinfo->srcport);
    gchar *msgnum = g_strdup_printf("%lu", value_message_num);
    gchar *colon = g_strdup(":");

    // TODO: this is a terrible memory leak .. it keeps creating new keys, never frees them
    gchar *hash_key = wmem_strconcat(
            pool,
            msg_type->str,
            colon,
            srcport,
            colon,
            msgnum,
            NULL
    );

    guint* first_frame_number_for_msg = wmem_map_lookup(conversation_entry_ptr->blip_requests, (void *) hash_key);

    if (first_frame_number_for_msg != NULL) {
        printf("found first_frame_number:%d for_msg: %llu with hash key: %s\n", *first_frame_number_for_msg, (unsigned long long)value_message_num, hash_key);
        if (*first_frame_number_for_msg != pinfo->num) {
            printf("first_frame_in_msg = FALSE;");
            first_frame_in_msg = FALSE;
        }
    } else {

        // If storing the key in the hashmap, re-allocate it with the file_scope() allocator
        gchar *hash_key_copy = wmem_strdup(wmem_file_scope(), hash_key);

        // Add entry to hashmap to track the frame number for this request message
        guint32* frame_num_copy = wmem_alloc(wmem_file_scope(), sizeof(guint32));
        *frame_num_copy = pinfo->num;

        wmem_map_insert(conversation_entry_ptr->blip_requests, (void *) hash_key_copy, (void *) frame_num_copy);

    }

    g_free(srcport);
    g_free(msgnum);
    g_free(colon);

    wmem_destroy_allocator(pool);  // destroy the temp memory pool


    return first_frame_in_msg;
}

static z_stream* get_decompress_stream(guint64 value_frame_flags)
{
    // Mask out the least significant bits: 0000 0111
    guint64 type_mask_val = (0x07ll & value_frame_flags);
    
    // MSG
    if (type_mask_val == 0x00ll) {
        return &decompress_stream_up;
    }
    
    return &decompress_stream_down;
}

static tvbuff_t*
decompress(packet_info* pinfo, tvbuff_t* tvb, z_stream* decompress_stream, gint offset, gint length)
{
    static Byte trailer[4] = { 0x00, 0x00, 0xff, 0xff };
    if(!decompress_stream->next_out) {
        decompress_stream->zalloc = 0;
        decompress_stream->zfree = 0;
        decompress_stream->opaque = 0;
        int err = inflateInit2(decompress_stream, -MAX_WBITS);
        if(err != Z_OK) {
            decompress_stream->next_out = 0;
            REPORT_DISSECTOR_BUG("Unable to create INFLATE context to decompress messages");
            return NULL;
        }
    }
    
    const guint8* buf = tvb_get_ptr(tvb, offset, length);
    decompress_stream->next_in = (Bytef*)buf;
    decompress_stream->avail_in = length;
    decompress_stream->next_out = decompress_buffer;
    decompress_stream->avail_out = 16384;
    uLong start = decompress_stream->total_out;
    int err = inflate(decompress_stream, Z_NO_FLUSH);
    if(err < 0) {
        printf("Error decompressing first step: %d\n", err);
        return NULL;
    }
    
    decompress_stream->next_in = trailer;
    decompress_stream->avail_in = 4;
    err = inflate(decompress_stream, Z_SYNC_FLUSH);
    if(err < 0) {
        printf("Error decompressing second step: %d\n", err);
        return NULL;
    }
    
    uLong bodyLength = decompress_stream->total_out - start;
    guint8* poolBuffer = (guint8*)wmem_alloc(pinfo->pool, bodyLength);
    memcpy(poolBuffer, decompress_buffer, bodyLength);
    tvbuff_t* decompressedChild = tvb_new_real_data(poolBuffer, (guint)bodyLength, (gint)bodyLength);
    add_new_data_source(pinfo, decompressedChild, "Decompressed Payload");
    return decompressedChild;
}

void
proto_register_blip(void)
{
    // Compressed = 0x08
    // Urgent     = 0x10
    // NoReply    = 0x20
    // MoreComing = 0x40
    // In ascending order so that a binary search will be used as per the
    // README.dissector
    static const value_string flag_combos[] = {
        { 0x00, "None" },
        { 0x08, "Compressed" },
        { 0x10, "Urgent" },
        { 0x20, "NoReply" },
        { 0x40, "MoreComing" },
        { 0x08|0x10, "Compressed|Urgent" },
        { 0x08|0x20, "Compressed|NoReply" },
        { 0x10|0x20, "Urgent|NoReply" },
        { 0x08|0x40, "Compressed|MoreComing" },
        { 0x10|0x40, "Urgent|MoreComing" },
        { 0x20|0x40, "NoReply|MoreComing" },
        { 0x08|0x10|0x20, "Compressed|Urgent|NoReply" },
        { 0x08|0x10|0x40, "Compressed|Urgent|MoreComing" },
        { 0x08|0x20|0x40, "Compressed|NoReply|MoreComing" },
        { 0x10|0x20|0x40, "Urgent|NoReply|MoreComing" },
        { 0x08|0x10|0x20|0x40, "Compressed|Urgent|NoReply|MoreComing" },
        { 0, NULL }
    };
    static value_string_ext flag_combos_ext = VALUE_STRING_EXT_INIT(flag_combos);
    
    static hf_register_info hf[] = {
            { &hf_blip_message_number,
                    { "Message Number", "blip.messagenum",
                            FT_UINT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_frame_flags,
                    { "Frame Flags", "blip.frameflags",
                            FT_UINT8, BASE_HEX|BASE_EXT_STRING,
                            &flag_combos_ext, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_properties_length,
                    { "Properties Length", "blip.propslength",
                            FT_UINT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_properties,
                    { "Properties", "blip.props",
                            FT_STRING, STR_UNICODE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_message_body,
                    { "Message Body", "blip.messagebody",
                            FT_STRING, STR_UNICODE,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_ack_size,
                    { "ACK num bytes", "blip.numackbytes",
                            FT_UINT64, BASE_DEC,
                            NULL, 0x0,
                            NULL, HFILL }
            },
            { &hf_blip_checksum,
                    { "Checksum", "blip.checksum",
                        FT_UINT32, BASE_DEC,
                        NULL, 0x0,
                        NULL, HFILL }
            }
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
