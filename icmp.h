#ifndef ICMP_H
#define ICMP_H

/* ICMPヘッダサイズ(8byte) */
#define ICMP_HDR_SIZE 8

/* ICMPメッセージ: エコー応答 */
#define ICMP_TYPE_ECHOREPLY           0
/* ICMPメッセージ: 宛先到達不能*/
#define ICMP_TYPE_DEST_UNREACH        3
/* ICMPメッセージ: 送信元抑制 */
#define ICMP_TYPE_SOURCE_QUENCH       4
/* ICMPメッセージ: リダイレクト */
#define ICMP_TYPE_REDIRECT            5
/* ICMPメッセージ: エコー要求 */
#define ICMP_TYPE_ECHO                8
/* ICMPメッセージ: 時間超過 */
#define ICMP_TYPE_TIME_EXCEEDED      11
/* ICMPメッセージ: パラメータ異常 */
#define ICMP_TYPE_PARAM_PROBLEM      12
/* ICMPメッセージ: タイムスタンプ要求 */
#define ICMP_TYPE_TIMESTAMP          13
/* ICMPメッセージ: タイムスタンプ応答 */
#define ICMP_TYPE_TIMESTAMPREPLY     14
/* ICMPメッセージ: 情報要求 */
#define ICMP_TYPE_INFO_REQUEST       15
/* ICMPメッセージ: 情報応答 */
#define ICMP_TYPE_INFO_REPLY         16


extern int
icmp_init(void);

#endif
