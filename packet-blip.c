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

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/tvbparse.h>
#include <wsutil/wsjsmn.h>

#include <wsutil/str_util.h>
#include <wsutil/unicode-utils.h>

#include <wiretap/wtap.h>
#include <printf.h>

#include "packet-http.h"

void proto_register_json(void);
void proto_reg_handoff_json(void);
static char *json_string_unescape(tvbparse_elem_t *tok);

static dissector_handle_t blip_handle;

static int proto_blip = -1;

static gint ett_json = -1;
static gint ett_json_array = -1;
static gint ett_json_object = -1;
static gint ett_json_member = -1;
/* Define the trees for json compact form */
static gint ett_json_compact = -1;
static gint ett_json_array_compact = -1;
static gint ett_json_object_compact = -1;
static gint ett_json_member_compact = -1;


#define BLIP_HFI_INIT HFI_INIT(proto_blip)

static header_field_info hfi_blip BLIP_HFI_INIT =
        { "BLIP", "blip", FT_NONE, BASE_NONE, NULL, 0x00, "BLIP", HFILL };

static header_field_info *hfi_json = NULL;

#define JSON_HFI_INIT HFI_INIT(proto_json)

static header_field_info hfi_json_array JSON_HFI_INIT =
        { "Array", "json.array", FT_NONE, BASE_NONE, NULL, 0x00, "JSON array", HFILL };

static header_field_info hfi_json_object JSON_HFI_INIT =
        { "Object", "json.object", FT_NONE, BASE_NONE, NULL, 0x00, "JSON object", HFILL };

static header_field_info hfi_json_member JSON_HFI_INIT =
        { "Member", "json.member", FT_NONE, BASE_NONE, NULL, 0x00, "JSON object member", HFILL };

static header_field_info hfi_json_key JSON_HFI_INIT =
        { "Key", "json.key", FT_STRING, STR_UNICODE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_json_value_string JSON_HFI_INIT = /* FT_STRINGZ? */
        { "String value", "json.value.string", FT_STRING, STR_UNICODE, NULL, 0x00, "JSON string value", HFILL };

static header_field_info hfi_json_value_number JSON_HFI_INIT = /* FT_DOUBLE/ FT_INT64? */
        { "Number value", "json.value.number", FT_STRING, BASE_NONE, NULL, 0x00, "JSON number value", HFILL };

static header_field_info hfi_json_value_false JSON_HFI_INIT =
        { "False value", "json.value.false", FT_NONE, BASE_NONE, NULL, 0x00, "JSON false value", HFILL };

static header_field_info hfi_json_value_null JSON_HFI_INIT =
        { "Null value", "json.value.null", FT_NONE, BASE_NONE, NULL, 0x00, "JSON null value", HFILL };

static header_field_info hfi_json_value_true JSON_HFI_INIT =
        { "True value", "json.value.true", FT_NONE, BASE_NONE, NULL, 0x00, "JSON true value", HFILL };

/* HFIs below are used only for compact form display */
static header_field_info hfi_json_array_compact JSON_HFI_INIT =
        { "Array compact", "json.array_compact", FT_NONE, BASE_NONE, NULL, 0x00, "JSON array compact", HFILL };

static header_field_info hfi_json_object_compact JSON_HFI_INIT =
        { "Object compact", "json.object_compact", FT_NONE, BASE_NONE, NULL, 0x00, "JSON object compact", HFILL };

static header_field_info hfi_json_member_compact JSON_HFI_INIT =
        { "Member compact", "json.member_compact", FT_NONE, BASE_NONE, NULL, 0x00, "JSON member compact", HFILL };

static header_field_info hfi_json_array_item_compact JSON_HFI_INIT =
        { "Array item compact", "json.array_item_compact", FT_NONE, BASE_NONE, NULL, 0x00, "JSON array item compact", HFILL };


/* Preferences */
static gboolean json_compact = FALSE;

static tvbparse_wanted_t* want;
static tvbparse_wanted_t* want_ignore;

//static dissector_handle_t text_lines_handle;

typedef enum {
    JSON_TOKEN_INVALID = -1,
    JSON_TOKEN_NUMBER = 0,
    JSON_TOKEN_STRING,
    JSON_TOKEN_FALSE,
    JSON_TOKEN_NULL,
    JSON_TOKEN_TRUE,

    /* not really tokens ... */
            JSON_OBJECT,
    JSON_ARRAY

} json_token_type_t;

typedef struct {
    wmem_stack_t *stack;
    wmem_stack_t *stack_compact; /* Used for compact json form only */
    wmem_stack_t *array_idx;	/* Used for compact json form only.
									Top item: -3.
									Object: < 0.
									Array -1: no key, -2: has key  */
} json_parser_data_t;

#define JSON_COMPACT_TOP_ITEM -3
#define JSON_COMPACT_OBJECT_WITH_KEY -2
#define JSON_COMPACT_OBJECT_WITHOUT_KEY -1
#define JSON_COMPACT_ARRAY 0

#define JSON_ARRAY_BEGIN(json_tvbparse_data) wmem_stack_push(json_tvbparse_data->array_idx, GINT_TO_POINTER(JSON_COMPACT_ARRAY))
#define JSON_OBJECT_BEGIN(json_tvbparse_data) wmem_stack_push(json_tvbparse_data->array_idx, GINT_TO_POINTER(JSON_COMPACT_OBJECT_WITHOUT_KEY))
#define JSON_ARRAY_OBJECT_END(json_tvbparse_data) wmem_stack_pop(json_tvbparse_data->array_idx)
#define JSON_INSIDE_ARRAY(idx) (idx >= JSON_COMPACT_ARRAY)
#define JSON_OBJECT_SET_HAS_KEY(idx) (idx == JSON_COMPACT_OBJECT_WITH_KEY)

static void
json_array_index_increment(json_parser_data_t *data)
{
    gint idx = GPOINTER_TO_INT(wmem_stack_pop(data->array_idx));
    idx++;
    wmem_stack_push(data->array_idx, GINT_TO_POINTER(idx));
}

static void
json_object_add_key(json_parser_data_t *data)
{
    wmem_stack_pop(data->array_idx);
    wmem_stack_push(data->array_idx, GINT_TO_POINTER(JSON_COMPACT_OBJECT_WITH_KEY));
}

static int
dissect_blip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{

    /* Set the protcol column to say BLIP */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BLIP");

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    /* Add a subtree to dissection.  See 9.2.2. Dissecting the details of the protocol of WSDG */

    // proto_tree_add_item(proto_tree *tree, int hfindex, tvbuff_t *tvb, const gint start, gint length, const guint encoding)

    proto_item *ti = proto_tree_add_item(tree, &hfi_blip, tvb, 0, -1, ENC_NA);
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

static void before_object(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
    json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

    proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
    proto_tree *subtree;
    proto_item *ti;

    ti = proto_tree_add_item(tree, &hfi_json_object, tok->tvb, tok->offset, tok->len, ENC_NA);

    subtree = proto_item_add_subtree(ti, ett_json_object);
    wmem_stack_push(data->stack, subtree);

    if (json_compact) {
        proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
        proto_tree *subtree_compact;
        proto_item *ti_compact;

        gint idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

        if (JSON_INSIDE_ARRAY(idx)) {
            ti_compact = proto_tree_add_none_format(tree_compact, hfi_json_object_compact.id, tok->tvb, tok->offset, tok->len, "%d:", idx);
            subtree_compact = proto_item_add_subtree(ti_compact, ett_json_object_compact);
            json_array_index_increment(data);
        } else {
            subtree_compact = tree_compact;
        }
        wmem_stack_push(data->stack_compact, subtree_compact);

        JSON_OBJECT_BEGIN(data);
    }
}

static void after_object(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *elem _U_) {
    json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

    wmem_stack_pop(data->stack);

    if (json_compact) {
        proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
        proto_item *parent_item = proto_tree_get_parent(tree_compact);

        gint idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

        if (JSON_OBJECT_SET_HAS_KEY(idx))
            proto_item_append_text(parent_item, " {...}");
        else
            proto_item_append_text(parent_item, " {}");

        wmem_stack_pop(data->stack_compact);

        JSON_ARRAY_OBJECT_END(data);
    }
}

static void before_member(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
    json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

    proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
    proto_tree *subtree;
    proto_item *ti;

    ti = proto_tree_add_item(tree, &hfi_json_member, tok->tvb, tok->offset, tok->len, ENC_NA);

    subtree = proto_item_add_subtree(ti, ett_json_member);
    wmem_stack_push(data->stack, subtree);

    if (json_compact) {
        proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
        proto_tree *subtree_compact;
        proto_item *ti_compact;

        tvbparse_elem_t *key_tok = tok->sub;

        if (key_tok && key_tok->id == JSON_TOKEN_STRING) {
            char *key_str = json_string_unescape(key_tok);
            ti_compact = proto_tree_add_none_format(tree_compact, hfi_json_member_compact.id, tok->tvb, tok->offset, tok->len, "%s:", key_str);
        } else {
            ti_compact = proto_tree_add_item(tree_compact, &hfi_json_member_compact, tok->tvb, tok->offset, tok->len, ENC_NA);
        }

        subtree_compact = proto_item_add_subtree(ti_compact, ett_json_member_compact);
        wmem_stack_push(data->stack_compact, subtree_compact);
    }
}

static void after_member(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
    json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

    proto_tree *tree = (proto_tree *)wmem_stack_pop(data->stack);

    if (tree) {
        tvbparse_elem_t *key_tok = tok->sub;

        if (key_tok && key_tok->id == JSON_TOKEN_STRING) {
            char *key = json_string_unescape(key_tok);

            proto_tree_add_string(tree, &hfi_json_key, key_tok->tvb, key_tok->offset, key_tok->len, key);
            proto_item_append_text(tree, " Key: %s", key);
        }
    }

    if (json_compact) {
        wmem_stack_pop(data->stack_compact);
        json_object_add_key(data);
    }
}

static void before_array(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
    json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

    proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
    proto_tree *subtree;
    proto_item *ti;

    ti = proto_tree_add_item(tree, &hfi_json_array, tok->tvb, tok->offset, tok->len, ENC_NA);

    subtree = proto_item_add_subtree(ti, ett_json_array);
    wmem_stack_push(data->stack, subtree);

    if (json_compact) {
        JSON_ARRAY_BEGIN(data);
    }
}

static void after_array(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *elem _U_) {
    json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

    wmem_stack_pop(data->stack);

    if (json_compact) {
        proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);
        proto_item *parent_item = proto_tree_get_parent(tree_compact);

        gint idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));
        if (idx == 0)
            proto_item_append_text(parent_item, " []");
        else
            proto_item_append_text(parent_item, " [...]");

        JSON_ARRAY_OBJECT_END(data);
    }
}

static int
json_tvb_memcpy_utf8(char *buf, tvbuff_t *tvb, int offset, int offset_max)
{
    int len = ws_utf8_char_len((guint8) *buf);

    /* XXX, before moving to core API check if it's off-by-one safe.
     * For JSON analyzer it's not a problem
     * (string always terminated by ", which is not valid UTF-8 continuation character) */
    if (len == -1 || ((guint) (offset + len)) >= (guint) offset_max) {
        *buf = '?';
        return 1;
    }

    /* assume it's valid UTF-8 */
    tvb_memcpy(tvb, buf + 1, offset + 1, len - 1);

    if (!g_utf8_validate(buf, len, NULL)) {
        *buf = '?';
        return 1;
    }

    return len;
}

static char *json_string_unescape(tvbparse_elem_t *tok)
{
    char *str = (char *)wmem_alloc(wmem_packet_scope(), tok->len - 1);
    int i, j;

    j = 0;
    for (i = 1; i < tok->len - 1; i++) {
        guint8 ch = tvb_get_guint8(tok->tvb, tok->offset + i);
        int bin;

        if (ch == '\\') {
            i++;

            ch = tvb_get_guint8(tok->tvb, tok->offset + i);
            switch (ch) {
                case '\"':
                case '\\':
                case '/':
                    str[j++] = ch;
                    break;

                case 'b':
                    str[j++] = '\b';
                    break;
                case 'f':
                    str[j++] = '\f';
                    break;
                case 'n':
                    str[j++] = '\n';
                    break;
                case 'r':
                    str[j++] = '\r';
                    break;
                case 't':
                    str[j++] = '\t';
                    break;

                case 'u':
                {
                    guint32 unicode_hex = 0;
                    gboolean valid = TRUE;
                    int k;

                    for (k = 0; k < 4; k++) {
                        i++;
                        unicode_hex <<= 4;

                        ch = tvb_get_guint8(tok->tvb, tok->offset + i);
                        bin = ws_xton(ch);
                        if (bin == -1) {
                            valid = FALSE;
                            break;
                        }
                        unicode_hex |= bin;
                    }

                    if ((IS_LEAD_SURROGATE(unicode_hex))) {
                        ch = tvb_get_guint8(tok->tvb, tok->offset + i + 1);

                        if (ch == '\\') {
                            i++;
                            ch = tvb_get_guint8(tok->tvb, tok->offset + i + 1);
                            if (ch == 'u') {
                                guint16 lead_surrogate = unicode_hex;
                                guint16 trail_surrogate = 0;
                                i++;

                                for (k = 0; k < 4; k++) {
                                    i++;
                                    trail_surrogate <<= 4;

                                    ch = tvb_get_guint8(tok->tvb, tok->offset + i);
                                    bin = ws_xton(ch);
                                    if (bin == -1) {
                                        valid = FALSE;
                                        break;
                                    }
                                    trail_surrogate |= bin;
                                }

                                if ((IS_TRAIL_SURROGATE(trail_surrogate))) {
                                    unicode_hex = SURROGATE_VALUE(lead_surrogate,trail_surrogate);
                                } else {
                                    valid = FALSE;
                                }
                            } else {
                                valid = FALSE;
                            }
                        } else {
                            valid = FALSE;
                        }
                    } else if ((IS_TRAIL_SURROGATE(unicode_hex))) {
                        i++;
                        valid = FALSE;
                    }

                    if (valid && g_unichar_validate(unicode_hex) && g_unichar_isprint(unicode_hex)) {
                        /* \uXXXX => 6 bytes */
                        int charlen = g_unichar_to_utf8(unicode_hex, &str[j]);
                        j += charlen;
                    } else
                        str[j++] = '?';
                    break;
                }

                default:
                    /* not valid by JSON grammar (also tvbparse rules should not allow it) */
                    DISSECTOR_ASSERT_NOT_REACHED();
                    break;
            }

        } else {
            int utf_len;

            str[j] = ch;
            /* XXX if it's not valid UTF-8 character, add some expert info? (it violates JSON grammar) */
            utf_len = json_tvb_memcpy_utf8(&str[j], tok->tvb, tok->offset + i, tok->offset + tok->len);
            j += utf_len;
            i += (utf_len - 1);
        }

    }
    str[j] = '\0';

    return str;
}

static void after_value(void *tvbparse_data, const void *wanted_data _U_, tvbparse_elem_t *tok) {
    json_parser_data_t *data = (json_parser_data_t *) tvbparse_data;

    proto_tree *tree = (proto_tree *)wmem_stack_peek(data->stack);
    json_token_type_t value_id = JSON_TOKEN_INVALID;

    if (tok->sub)
        value_id = (json_token_type_t)tok->sub->id;

    switch (value_id) {
        case JSON_TOKEN_STRING:
            if (tok->len >= 2)
                proto_tree_add_string(tree, &hfi_json_value_string, tok->tvb, tok->offset, tok->len, json_string_unescape(tok));
            else
                proto_tree_add_item(tree, &hfi_json_value_string, tok->tvb, tok->offset, tok->len, ENC_ASCII|ENC_NA);
            break;

        case JSON_TOKEN_NUMBER:
            /* XXX, convert to number */
            proto_tree_add_item(tree, &hfi_json_value_number, tok->tvb, tok->offset, tok->len, ENC_ASCII|ENC_NA);
            break;

        case JSON_TOKEN_FALSE:
            proto_tree_add_item(tree, &hfi_json_value_false, tok->tvb, tok->offset, tok->len, ENC_NA);
            break;

        case JSON_TOKEN_NULL:
            proto_tree_add_item(tree, &hfi_json_value_null, tok->tvb, tok->offset, tok->len, ENC_NA);
            break;

        case JSON_TOKEN_TRUE:
            proto_tree_add_item(tree, &hfi_json_value_true, tok->tvb, tok->offset, tok->len, ENC_NA);
            break;

        case JSON_OBJECT:
        case JSON_ARRAY:
            /* already added */
            break;

        default:
            proto_tree_add_format_text(tree, tok->tvb, tok->offset, tok->len);
            break;
    }

    if (json_compact) {
        proto_tree *tree_compact = (proto_tree *)wmem_stack_peek(data->stack_compact);

        gint idx = GPOINTER_TO_INT(wmem_stack_peek(data->array_idx));

        char *val_str = tvb_get_string_enc(wmem_packet_scope(), tok->tvb, tok->offset, tok->len, ENC_UTF_8);

        if (value_id == JSON_OBJECT || value_id == JSON_ARRAY) {
            return;
        }

        if (JSON_INSIDE_ARRAY(idx)) {
            proto_tree_add_none_format(tree_compact, hfi_json_array_item_compact.id, tok->tvb, tok->offset, tok->len, "%d: %s", idx, val_str);
            json_array_index_increment(data);
        } else {
            proto_item *parent_item = proto_tree_get_parent(tree_compact);
            proto_item_append_text(parent_item, " %s", val_str);
        }
    }
}

static void init_json_parser(void) {
    static tvbparse_wanted_t _want_object;
    static tvbparse_wanted_t _want_array;

    tvbparse_wanted_t *want_object, *want_array;
    tvbparse_wanted_t *want_member;
    tvbparse_wanted_t *want_string;
    tvbparse_wanted_t *want_number, *want_int;
    tvbparse_wanted_t *want_value;
    tvbparse_wanted_t *want_value_separator;

#define tvbparse_optional(id, private_data, before_cb, after_cb, wanted) \
	tvbparse_some(id, 0, 1, private_data, before_cb, after_cb, wanted)

    tvbparse_wanted_t *want_quot = tvbparse_char(-1,"\"",NULL,NULL,NULL);

    want_string = tvbparse_set_seq(JSON_TOKEN_STRING, NULL, NULL, NULL,
                                   want_quot,
                                   tvbparse_some(-1, 0, G_MAXINT, NULL, NULL, NULL,
                                                 tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                                                    tvbparse_not_chars(-1, 0, 0, "\"" "\\", NULL, NULL, NULL), /* XXX, without invalid unicode characters */
                                                                    tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                                     tvbparse_char(-1, "\\", NULL, NULL, NULL),
                                                                                     tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                                                                                        tvbparse_chars(-1, 0, 1, "\"" "\\" "/bfnrt", NULL, NULL, NULL),
                                                                                                        tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                                                                         tvbparse_char(-1, "u", NULL, NULL, NULL),
                                                                                                                         tvbparse_chars(-1, 4, 4, "0123456789abcdefABCDEF", NULL, NULL, NULL),
                                                                                                                         NULL),
                                                                                                        NULL),
                                                                                     NULL),
                                                                    NULL)
                                   ),
                                   want_quot,
                                   NULL);

    want_value_separator = tvbparse_char(-1, ",", NULL, NULL, NULL);

    /* int = zero / ( digit1-9 *DIGIT ) */
    want_int = tvbparse_set_oneof(-1, NULL, NULL, NULL,
                                  tvbparse_char(-1, "0", NULL, NULL, NULL),
                                  tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                   tvbparse_chars(-1, 1, 1, "123456789", NULL, NULL, NULL),
                                                   tvbparse_optional(-1, NULL, NULL, NULL, /* tvbparse_chars() don't respect 0 as min_len ;/ */
                                                                     tvbparse_chars(-1, 0, 0, "0123456789", NULL, NULL, NULL)),
                                                   NULL),
                                  NULL);

    /* number = [ minus ] int [ frac ] [ exp ] */
    want_number = tvbparse_set_seq(JSON_TOKEN_NUMBER, NULL, NULL, NULL,
                                   tvbparse_optional(-1, NULL, NULL, NULL, /* tvbparse_chars() don't respect 0 as min_len ;/ */
                                                     tvbparse_chars(-1, 0, 1, "-", NULL, NULL, NULL)),
                                   want_int,
            /* frac = decimal-point 1*DIGIT */
                                   tvbparse_optional(-1, NULL, NULL, NULL,
                                                     tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                      tvbparse_char(-1, ".", NULL, NULL, NULL),
                                                                      tvbparse_chars(-1, 1, 0, "0123456789", NULL, NULL, NULL),
                                                                      NULL)),
            /* exp = e [ minus / plus ] 1*DIGIT */
                                   tvbparse_optional(-1, NULL, NULL, NULL,
                                                     tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                      tvbparse_char(-1, "eE", NULL, NULL, NULL),
                                                                      tvbparse_optional(-1, NULL, NULL, NULL, /* tvbparse_chars() don't respect 0 as min_len ;/ */
                                                                                        tvbparse_chars(-1, 0, 1, "-+", NULL, NULL, NULL)),
                                                                      tvbparse_chars(-1, 1, 0, "0123456789", NULL, NULL, NULL),
                                                                      NULL)),
                                   NULL);

    /* value = false / null / true / object / array / number / string */
    want_value = tvbparse_set_oneof(-1, NULL, NULL, after_value,
                                    tvbparse_string(JSON_TOKEN_FALSE, "false", NULL, NULL, NULL),
                                    tvbparse_string(JSON_TOKEN_NULL, "null", NULL, NULL, NULL),
                                    tvbparse_string(JSON_TOKEN_TRUE, "true", NULL, NULL, NULL),
                                    &_want_object,
                                    &_want_array,
                                    want_number,
                                    want_string,
                                    NULL);

    /* array = begin-array [ value *( value-separator value ) ] end-array */
    want_array = tvbparse_set_seq(JSON_ARRAY, NULL, before_array, after_array,
                                  tvbparse_char(-1, "[", NULL, NULL, NULL),
                                  tvbparse_optional(-1, NULL, NULL, NULL,
                                                    tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                     want_value,
                                                                     tvbparse_some(-1, 0, G_MAXINT, NULL, NULL, NULL,
                                                                                   tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                                                    want_value_separator,
                                                                                                    want_value,
                                                                                                    NULL)),
                                                                     NULL)
                                  ),
                                  tvbparse_char(-1, "]", NULL, NULL, NULL),
                                  NULL);
    _want_array = *want_array;

    /* member = string name-separator value */
    want_member = tvbparse_set_seq(-1, NULL, before_member, after_member,
                                   want_string,
                                   tvbparse_char(-1, ":", NULL, NULL, NULL),
                                   want_value,
                                   NULL);

    /* object = begin-object [ member *( value-separator member ) ] end-object */
    want_object = tvbparse_set_seq(JSON_OBJECT, NULL, before_object, after_object,
                                   tvbparse_char(-1, "{", NULL, NULL, NULL),
                                   tvbparse_optional(-1, NULL, NULL, NULL,
                                                     tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                      want_member,
                                                                      tvbparse_some(-1, 0, G_MAXINT, NULL, NULL, NULL,
                                                                                    tvbparse_set_seq(-1, NULL, NULL, NULL,
                                                                                                     want_value_separator,
                                                                                                     want_member,
                                                                                                     NULL)),
                                                                      NULL)
                                   ),
                                   tvbparse_char(-1, "}", NULL, NULL, NULL),
                                   NULL);
    _want_object = *want_object;

    want_ignore = tvbparse_chars(-1, 1, 0, " \t\r\n", NULL, NULL, NULL);

    /* JSON-text = object / array */
    want = tvbparse_set_oneof(-1, NULL, NULL, NULL,
                              want_object,
                              want_array,
            /* tvbparse_not_chars(-1, 1, 0, " \t\r\n", NULL, NULL, NULL), */
                              NULL);

    /* XXX, heur? */
}



void
proto_register_blip(void)
{
    static gint *ett[] = {
            &ett_json,
            &ett_json_array,
            &ett_json_object,
            &ett_json_member,
            &ett_json_compact,
            &ett_json_array_compact,
            &ett_json_object_compact,
            &ett_json_member_compact
    };

#ifndef HAVE_HFI_SECTION_INIT
    static header_field_info *hfi[] = {
            &hfi_json_array,
            &hfi_json_object,
            &hfi_json_member,
            &hfi_json_key,
            &hfi_json_value_string,
            &hfi_json_value_number,
            &hfi_json_value_false,
            &hfi_json_value_null,
            &hfi_json_value_true,
            &hfi_json_array_compact,
            &hfi_json_object_compact,
            &hfi_json_member_compact,
            &hfi_json_array_item_compact,
    };
#endif

    module_t *json_module;

    proto_blip = proto_register_protocol("BLIP Couchbase Mobile", "BLIP", "blip");


    hfi_json = proto_registrar_get_nth(proto_blip);

    proto_register_fields(proto_blip, hfi, array_length(hfi));
    proto_register_subtree_array(ett, array_length(ett));

    blip_handle = register_dissector("blip", dissect_blip, proto_blip);

    init_json_parser();

    json_module = prefs_register_protocol(proto_blip, NULL);
    prefs_register_bool_preference(json_module, "compact_form",
                                   "Display BLIP in compact form",
                                   "Display BLIP like in browsers devtool",
                                   &json_compact);
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
