#ifndef ROCWS_H
#define ROCWS_H

#define WSGUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
#define ROCWS_TCP_CONNECTED 0 /*tcp连接建立*/
#define ROCWS_WS_CONNECTED 1  /*websocket连接建立*/
#define ROCWS_WS_CLOSED 2     /*websocket连接断开*/
#define ROCWS_TCP_CLOSED 3    /*tcp连接断开*/

#define ROCWS_FRAME_DATA_CONTINUE 0x0
#define ROCWS_FRAME_DATA_TEXT 0x1
#define ROCWS_FRAME_DATA_BINARY 0x2
#define ROCWS_FRAME_CTRL_CLOSE 0x8
#define ROCWS_FRAME_CTRL_PING 0x9
#define ROCWS_FRAME_CTRL_PONG 0xA

#define ROCWS_FRAME_GET_STATUS 0
#define ROCWS_FRAME_GET_MASKPAYLOADLEN 1
#define ROCWS_FRAME_GET_PAYLOADLEN16 2
#define ROCWS_FRAME_GET_PAYLOADLEN64 3
#define ROCWS_FRAME_GET_MASKINGKEY 4
#define ROCWS_FRAME_GET_DATA 5

/*
-+------------+-----------------+-----------|
 |Status Code | Meaning         | Reference |
-+------------+-----------------+-----------|
 | 1000       | Normal Closure  | RFC 6455  |
-+------------+-----------------+-----------|
 | 1001       | Going Away      | RFC 6455  |
-+------------+-----------------+-----------|
 | 1002       | Protocol error  | RFC 6455  |
-+------------+-----------------+-----------|
 | 1003       | Unsupported Data| RFC 6455  |
-+------------+-----------------+-----------|
 | 1004       | ---Reserved---- | RFC 6455  |
-+------------+-----------------+-----------|
 | 1005       | No Status Rcvd  | RFC 6455  |
-+------------+-----------------+-----------|
 | 1006       | Abnormal Closure| RFC 6455  |
-+------------+-----------------+-----------|
 | 1007       | Invalid frame   | RFC 6455  |
 |            | payload data    |           |
-+------------+-----------------+-----------|
 | 1008       | Policy Violation| RFC 6455  |
-+------------+-----------------+-----------|
 | 1009       | Message Too Big | RFC 6455  |
-+------------+-----------------+-----------|
 | 1010       | Mandatory Ext.  | RFC 6455  |
-+------------+-----------------+-----------|
 | 1011       | Internal Server | RFC 6455  |
 |            | Error           |           |
-+------------+-----------------+-----------|
 | 1015       | TLS handshake   | RFC 6455  |
-+------------+-----------------+-----------|
*/
#define ROCWS_STATUS_CODE_NORMAL_CLOSE 1000
#define ROCWS_STATUS_CODE_GOING_AWAY 1001
#define ROCWS_STATUS_CODE_PROTOCOL_ERR 1002
#define ROCWS_STATUS_CODE_UNSUPPORTED_DATA 1003
#define ROCWS_STATUS_CODE_NO_STATUS_RECVED 1005
#define ROCWS_STATUS_CODE_ABNORMAL_CLOSE 1006
#define ROCWS_STATUS_CODE_INVALID_PAYLOAD 1007
#define ROCWS_STATUS_CODE_POLICY_VIOLATION 1008
#define ROCWS_STATUS_CODE_MSG_TOO_LONG 1009
#define ROCWS_STATUS_CODE_MANDATORY_EXIT 1010
#define ROCWS_STATUS_CODE_INTERNAL_SVR_ERR 1011
#define ROCWS_STATUS_CODE_TLS_HANDSHAKE 1015

#define ROCWS_MAXPAYLOADLEN_PER_FRAME 130172

#include <stdint.h>
#include <stdlib.h>
#include "roc_interface.h"

class ws_link
{
  public:
    ws_link(roc_link *link_)
    {
        _link = link_;
        _data = (char *)malloc(_data_size);
        if (!_data)
        {
            _data = nullptr;
        }
    }
    void umask(char *data, int len, char *mask);
    void tcp_recv();
    void tcp_close();
    void ws_handshake();
    void ws_recv();
    void ws_send(char *data, int len);
    void ws_ping();
    void ws_pong();
    void ws_close(uint16_t close_code); /*主动发送关闭帧,或响应关闭帧*/
    int ws_recv_handshake_req();        /*握手消息是否已全部接受*/
    int ws_make_frame(uint8_t fin, uint8_t op_code, uint8_t mask,
                      uint64_t payload_len, uint32_t masking_key,
                      char *payload_data, unsigned char *&frame);

  private:
    roc_link *_link;
    int _status = ROCWS_TCP_CONNECTED;
    char *_data = nullptr;
    uint32_t _data_len = 0;
    uint32_t _data_size = 1024;
    uint32_t _endstr_n = 0;
    uint32_t _lacking_bytes = 0;

    uint8_t _next_step = ROCWS_FRAME_GET_STATUS;
    uint8_t _fin = 0;
    uint8_t _op_code = 0; /*低4位存储数据帧Opcode,高4位存储控制帧Opcode*/
    uint8_t _mask = 0;
    uint64_t _payload_len = 0;
    char _masking_key[4] = {0, 0, 0, 0};
};
extern roc_send_func *tcp_send;
#endif /* ROCWS_H */
