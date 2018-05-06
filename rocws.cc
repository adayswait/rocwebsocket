#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <algorithm>
#include "rocws.h"
#include "sha1.h"
#include "base64.h"

#define HANDSHAKE_FORMAT ("\
HTTP/1.1 101 Switching Protocols\r\n\
Upgrade: websocket\r\n\
Connection: Upgrade\r\n\
Sec-WebSocket-Accept: %s\r\n\r\n")

void ws_link::tcp_recv()
{
    if (_status == ROCWS_TCP_CONNECTED)
    {
        if (ws_recv_handshake_req())
        {
            ws_handshake();
            _data_len = 0; /*标识数据清除*/
            if (_link->ibuf->tail - _link->ibuf->head != 0)
            {
                ws_recv();
            }
        }
        return;
    }
    if (_status == ROCWS_WS_CONNECTED)
    {
        ws_recv();
        return;
    }
}
void ws_link::tcp_close()
{
}

void ws_link::ws_handshake()
{
    if (_data == nullptr)
    {
        return;
    }
    char *tarstr = strstr(_data, "Sec-WebSocket-Key");
    char rstr[61];
    memset(rstr, 0, sizeof(rstr));
    if (tarstr)
    {
        tarstr += 19;
        strncpy(rstr, tarstr, 24);
        strcat(rstr, WSGUID);
        char sha1ret[21];
        sha1ret[20] = '\0';
        sha1(sha1ret, rstr, 60);
        char b64ret[29];
        b64ret[28] = '\0';
        base64_encode((unsigned char *)sha1ret, 20, b64ret);
        char head[130];
        head[129] = '\0';
        snprintf(head, 130, HANDSHAKE_FORMAT, b64ret);
        tcp_send(_link, head, 129);
        _status = ROCWS_WS_CONNECTED;
    }
}

void ws_link::ws_recv()
{
    roc_ringbuf *rb = _link->ibuf;
    char s7[8];
    s7[7] = '\0';
    roc_ringbuf_read(rb, s7, 7);
    rb->head -= 7;
    int i;
    for (i = 0; i < 7; i++)
    {
        uint8_t a = (uint8_t)s7[i];
    }

    char tempstr[8];
    switch (_next_step)
    {
    case ROCWS_FRAME_GET_STATUS:

    {
    ROCWS_FRAME_GET_STATUS_LABEL:
        roc_ringbuf_read(rb, tempstr, 1);
        uint8_t status = (uint8_t)(tempstr[0]);
        _fin = (status & 0xf0) == 0x80;
        uint8_t opcode = status & 0xf;
        if (opcode)
        {
            _op_code |= opcode;
        }
        _next_step = ROCWS_FRAME_GET_MASKPAYLOADLEN;
        if (rb->tail - rb->head == 0)
        {
            break;
        }
        else
        {
            goto ROCWS_FRAME_GET_MASKPAYLOADLEN_LABEL;
        }
    }

    case ROCWS_FRAME_GET_MASKPAYLOADLEN:
    {
    ROCWS_FRAME_GET_MASKPAYLOADLEN_LABEL:
        roc_ringbuf_read(rb, tempstr, 1);
        uint8_t status = (uint8_t)(tempstr[0]);
        _mask = status & 0x80;
        _payload_len = status & 0x7f;

        if (_payload_len == 126)
        {
            if (rb->tail - rb->head < 2)
            {
                _next_step = ROCWS_FRAME_GET_PAYLOADLEN16;
                break;
            }
            else
            {
                goto ROCWS_FRAME_GET_PAYLOADLEN16_LABEL;
            }
        }

        if (_payload_len == 127)
        {
            if (rb->tail - rb->head < 8)
            {
                _next_step = ROCWS_FRAME_GET_PAYLOADLEN64;
                break;
            }
            else
            {
                goto ROCWS_FRAME_GET_PAYLOADLEN64_LABEL;
            }
        }

        if (_payload_len < 126)
        {
            _lacking_bytes = _payload_len;
            if (_mask)
            {
                _next_step = ROCWS_FRAME_GET_MASKINGKEY;
                if (rb->tail - rb->head < 4)
                {
                    break;
                }
                else
                {
                    goto ROCWS_FRAME_GET_MASKINGKEY_LABEL;
                }
            }
            else
            {
                _next_step = ROCWS_FRAME_GET_DATA;
                if (rb->tail - rb->head == 0)
                {
                    break;
                }
                else
                {
                    goto ROCWS_FRAME_GET_DATA_LABEL;
                }
            }
        }
    }
    case ROCWS_FRAME_GET_PAYLOADLEN16:
    {
    ROCWS_FRAME_GET_PAYLOADLEN16_LABEL:
        roc_ringbuf_read(rb, tempstr, 2);
        uint16_t len_h = (uint8_t)(tempstr[0]);
        uint16_t len_l = (uint8_t)(tempstr[1]);
        _payload_len = (len_h << 8 | len_l);
        _lacking_bytes = _payload_len;
        if (_mask)
        {
            _next_step = ROCWS_FRAME_GET_MASKINGKEY;
            if (rb->tail - rb->head < 4)
            {
                break;
            }
            else
            {
                goto ROCWS_FRAME_GET_MASKINGKEY_LABEL;
            }
        }
        else
        {
            _next_step = ROCWS_FRAME_GET_DATA;
            if (rb->tail - rb->head == 0)
            {
                break;
            }
            else
            {
                goto ROCWS_FRAME_GET_DATA_LABEL;
            }
        }
    }
    case ROCWS_FRAME_GET_PAYLOADLEN64:
    {
    ROCWS_FRAME_GET_PAYLOADLEN64_LABEL:
        _payload_len = 0;
        roc_ringbuf_read(rb, tempstr, 8);
        int i;
        for (i = 0; i < 8; i++)
        {
            _payload_len = (_payload_len |
                            ((uint8_t)tempstr[i] << (8 * (7 - i))));
        }
        _lacking_bytes = _payload_len;
        if (_mask)
        {
            _next_step = ROCWS_FRAME_GET_MASKINGKEY;
            if (rb->tail - rb->head < 4)
            {
                break;
            }
            else
            {
                goto ROCWS_FRAME_GET_MASKINGKEY_LABEL;
            }
        }
        else
        {
            _next_step = ROCWS_FRAME_GET_DATA;
            if (rb->tail - rb->head == 0)
            {
                break;
            }
            else
            {
                goto ROCWS_FRAME_GET_DATA_LABEL;
            }
        }
    }
    case ROCWS_FRAME_GET_MASKINGKEY:
    {
    ROCWS_FRAME_GET_MASKINGKEY_LABEL:
        roc_ringbuf_read(rb, _masking_key, 4);
        _next_step = ROCWS_FRAME_GET_DATA;
        if (rb->tail - rb->head == 0)
        {
            break;
        }
        else
        {
            goto ROCWS_FRAME_GET_DATA_LABEL;
        }
    }
    case ROCWS_FRAME_GET_DATA:
    {
    ROCWS_FRAME_GET_DATA_LABEL:
        uint32_t uulen = _data_size - _data_len;
        uint32_t getlen = rb->tail - rb->head;
        getlen = getlen > _lacking_bytes ? _lacking_bytes : getlen;
        if (getlen >= uulen)
        {
            char *bak = _data;
            uint32_t bak_size = _data_size;
            _data_size = _data_size + getlen - uulen;
            _data = (char *)realloc(_data, _data_size + 1);
            if (!_data)
            {
                _data_size = bak_size;
                _data = bak;
                return;
            }
        }
        char *uu = _data + _data_len;
        roc_ringbuf_read(rb, uu, getlen);
        _data_len += getlen;
        if (getlen >= _lacking_bytes)
        {
            _next_step = ROCWS_FRAME_GET_STATUS;
            if (_fin)
            {
                if (_mask)
                {
                    umask(_data, _data_len, _masking_key);
                }
                *(_data + _data_len) = '\0';
                //ws_send(_data, _data_len);
                _link->next_plugin_level++;
                if (_link->svr->plugin[_link->next_plugin_level].level != -1)
                {

                    _link->svr->plugin[_link->next_plugin_level]
                        .recv_handler(_link, _data);
                }
                else
                {
                    _link->next_plugin_level = 0;
                }
            }
            _fin = 0;
            _data_len = 0;
        }
        _lacking_bytes = 0;
        _payload_len = 0;
        if (rb->tail - rb->head > 0)
        {
            return ws_recv();
        }
        else
        {
            *(_data + _data_len) = '\0';
            _lacking_bytes = _lacking_bytes - getlen;
            return;
        }
    } /* case ends */
    } /* switch ends */
}

int ws_link::ws_make_frame(uint8_t fin, uint8_t op_code, uint8_t mask,
                           uint64_t payload_len, uint32_t masking_key,
                           char *payload_data, unsigned char *&frame)
{
    uint64_t frame_len = 2;
    uint8_t op_frame_idx = 0;
    uint8_t _payload_len = 0;
    if (mask)
    {
        frame_len += 4;
    }
    if (payload_len < 126)
    {
        _payload_len = payload_len;
    }
    else if (payload_len < 65536)
    {
        _payload_len = 126;
        frame_len += 2;
    }
    else
    {
        _payload_len = 127;
        frame_len += 8;
    }
    frame_len += payload_len;
    frame = (unsigned char *)malloc(frame_len);
    if (!frame)
    {
        return 0;
    }
    *frame = ((fin ? 1 : 0) << 7) | op_code;
    *(frame + 1) = ((mask ? 1 : 0) << 7) | _payload_len;
    if (_payload_len == 126)
    {
        *(frame + 2) = payload_len >> 8;
        *(frame + 3) = payload_len & 0xff;
        op_frame_idx = 4;
    }
    else if (_payload_len == 127)
    {
        *(frame + 2) = (payload_len >> 56) & 0xff;
        *(frame + 3) = (payload_len >> 48) & 0xff;
        *(frame + 4) = (payload_len >> 40) & 0xff;
        *(frame + 5) = (payload_len >> 32) & 0xff;
        *(frame + 6) = (payload_len >> 24) & 0xff;
        *(frame + 7) = (payload_len >> 16) & 0xff;
        *(frame + 8) = (payload_len >> 8) & 0xff;
        *(frame + 9) = payload_len & 0xff;
        op_frame_idx = 10;
    }
    else
    {
        op_frame_idx = 2;
    }
    if (mask)
    {
        *(frame + op_frame_idx++) = (masking_key >> 24) & 0xff;
        *(frame + op_frame_idx++) = (masking_key >> 16) & 0xff;
        *(frame + op_frame_idx++) = (masking_key >> 8) & 0xff;
        *(frame + op_frame_idx++) = masking_key & 0xff;
    }
    if (payload_len != 0)
    {
        memcpy(frame + op_frame_idx, payload_data, payload_len);
    }
    return frame_len;
}

void ws_link::ws_send(char *data, int len)
{
    //单帧最大负载 130172 bytes
    if (len <= ROCWS_MAXPAYLOADLEN_PER_FRAME)
    {
        unsigned char *frame;
        int frame_len = ws_make_frame(1, ROCWS_FRAME_DATA_TEXT,
                                      0, len, 0, data, frame);
        if (frame_len != 0)
        {
            tcp_send(_link, frame, frame_len);
            free(frame);
        }
    }
    else
    {
        int i;
        int frame_pieces_n = len / ROCWS_MAXPAYLOADLEN_PER_FRAME;
        int last_payload_len = len % ROCWS_MAXPAYLOADLEN_PER_FRAME;
        if (last_payload_len == 0)
        {
            last_payload_len = ROCWS_MAXPAYLOADLEN_PER_FRAME;
        }
        else
        {
            frame_pieces_n += 1;
        }
        for (i = 0; i < frame_pieces_n; i++)
        {
            if (i == 0)
            {
                unsigned char *frame;
                int frame_len = ws_make_frame(
                    0, ROCWS_FRAME_DATA_TEXT,
                    0, ROCWS_MAXPAYLOADLEN_PER_FRAME,
                    0, data + ROCWS_MAXPAYLOADLEN_PER_FRAME * i,
                    frame);
                if (frame_len != 0)
                {
                    tcp_send(_link, frame, frame_len);
                    free(frame);
                }
            }
            else if (i != frame_pieces_n - 1)
            {
                unsigned char *frame;
                int frame_len = ws_make_frame(
                    0, 0,
                    0, ROCWS_MAXPAYLOADLEN_PER_FRAME,
                    0, data + ROCWS_MAXPAYLOADLEN_PER_FRAME * i,
                    frame);
                if (frame_len != 0)
                {
                    tcp_send(_link, frame, frame_len);
                    free(frame);
                }
            }
            else
            {
                unsigned char *frame;
                int frame_len = ws_make_frame(
                    1, ROCWS_FRAME_DATA_TEXT,
                    0, last_payload_len,
                    0, data + ROCWS_MAXPAYLOADLEN_PER_FRAME * i,
                    frame);
                if (frame_len != 0)
                {
                    tcp_send(_link, frame, frame_len);
                    free(frame);
                }
            }
        }
    }
}

int ws_link::ws_recv_handshake_req()
{
    if (_status != ROCWS_TCP_CONNECTED)
    {
        return 0;
    }
    roc_ringbuf *rb = _link->ibuf;
    uint32_t len = rb->tail - rb->head;
    uint32_t head_readable;
    len = std::min(len, rb->tail - rb->head);
    head_readable = std::min(len, rb->size - (rb->head & (rb->size - 1)));
    int i;
    for (i = 0; i < head_readable; i++)
    {
        char c = *(rb->data + (rb->head & (rb->size - 1)) + i);
        *(_data + _data_len + i) = c;
        if ((c == '\r' && (_endstr_n == 0 || _endstr_n == 2)) ||
            (c == '\n' && (_endstr_n == 1 || _endstr_n == 3)))
        {
            _endstr_n += 1;
        }
        else
        {
            _endstr_n = 0;
        }
        if (_endstr_n == 4)
        {
            rb->head += (_data_len + i + 1);
            _data_len += (i + 1);
            *(_data + _data_len) = '\0';
            return 1;
        }
    }
    _data_len += i;
    rb->head += i;

    for (i = 0; i < len - head_readable; i++)
    {
        char c = *(rb->data + i);
        *(_data + _data_len + i) = c;
        if ((c == '\r' && (_endstr_n == 0 || _endstr_n == 2)) ||
            (c == '\n' && (_endstr_n == 1 || _endstr_n == 3)))
        {
            _endstr_n += 1;
        }
        else
        {
            _endstr_n = 0;
        }
        if (_endstr_n == 4)
        {
            rb->head += (_data_len + i + 1);
            _data_len += (i + 1);
            *(_data + _data_len) = '\0';
            return 1;
        }
    }
    _data_len += i;
    rb->head += i;
    return 0;
}

void ws_link::umask(char *data, int len, char *mask)
{
    int i;
    for (i = 0; i < len; ++i)
    {
        *(data + i) ^= *(mask + (i % 4));
    }
}
