#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "util.h"
#include "net.h"
#include "ether.h"
#include "arp.h"
#include "ip.h"

/* see https://www.iana.org/assignments/arp-parameters/arp-parameters.txt */
/* ハードウェアアドレス種別：Ethernet */
#define ARP_HDR_ETHER 0x0001
/* NOTE: use same value as the Ethernet types */
/* プロトコルアドレス種別：IP */
#define ARP_PRO_IP ETHER_TYPE_IP

#define ARP_OP_REQUEST  1
#define ARP_OP_REPLY    2

/**
 * ARP ヘッダ構造体
 */
struct arp_hdr {
    /* Hardware Address Space (ハードウェアアドレス種別) */
    uint16_t hrd;
    /* Protocol Address Space (プロトコルアドレス種別) */
    uint16_t pro;
    /* Hardware Address Length (ハードウェアアドレス長)*/
    uint8_t hln;
    /* Protocol Address Length (プロトコルアドレス長) */
    uint8_t pln;
    /* Operation Code (オペレーションコード) */
    uint16_t op;
};

/**
 * (Ethernet/IPペアのための)ARP メッセージ構造体
 */
struct arp_ether_ip {
    /* ARP ヘッダ */
    struct arp_hdr hdr;
    /* Sender Hardware Address (送信元ハードウェアアドレス) */
    uint8_t sha[ETHER_ADDR_LEN];
    /* Sender Protocol Address (送信元プロトコルアドレス) */
    uint8_t spa[IP_ADDR_LEN];
    /* Target Hardware Address (ターゲット・ハードウェアアドレス) */
    uint8_t tha[ETHER_ADDR_LEN];
    /* Target Protocol Address (ターゲット・プロトコルアドレス) */
    uint8_t tpa[IP_ADDR_LEN];
};

/**
 * ARP Operation Code を文字列に変換
 * Network To ASCII
 * @param [in] type ARP Operation Code
 * @return ARP Operation Code(ASCII)
 */
static char *
arp_opcode_ntoa(uint16_t opcode)
{
    switch (ntoh16(opcode)) {
    case ARP_OP_REQUEST:
        return "Request";
    case ARP_OP_REPLY:
        return "Reply";
    }
    return "Unknown";
}

/**
 * デバッグ出力
 * @param [in] data データポインタ
 * @param [in] len データサイズ
 */
static void
arp_dump(const uint8_t *data, size_t len)
{
    struct arp_ether_ip *message;
    ip_addr_t spa, tpa;
    char addr[128];

    /* ここでは Ethernet/IP ペアのメッセージとみなす */
    message = (struct arp_ether_ip *)data;
    flockfile(stderr);
    fprintf(stderr, "        hrd: 0x%04x\n", ntoh16(message->hdr.hrd));
    fprintf(stderr, "        pro: 0x%04x\n", ntoh16(message->hdr.pro));
    fprintf(stderr, "        hln: %u\n", message->hdr.hln);
    fprintf(stderr, "        pln: %u\n", message->hdr.pln);
    fprintf(stderr, "         op: %u (%s)\n", ntoh16(message->hdr.op), arp_opcode_ntoa(message->hdr.op));
    
    /* ハードウェアアドレス(sha/tha) ･･･ Ethernetアドレス(MACアドレス) */
    /* プロトコルアドレス(spa/tpa) ･･･ IPアドレス */
    fprintf(stderr, "        sha: %s\n", ether_addr_ntop(message->sha, addr, sizeof(addr)));
    /* spa が uint8_t[4] なので一旦 memcpy() で ip_addr_t の変数へ取り出す */
    memcpy(&spa, message->spa, sizeof(spa));
    fprintf(stderr, "        spa: %s\n", ip_addr_ntop(spa, addr, sizeof(addr)));
    fprintf(stderr, "        tha: %s\n", ether_addr_ntop(message->tha, addr, sizeof(addr)));
    /* tpa も同様に memcpy() で ip_addr_t の変数へ取り出す */
    memcpy(&tpa, message->tpa, sizeof(tpa));
    fprintf(stderr, "        tpa: %s\n", ip_addr_ntop(tpa, addr, sizeof(addr)));
#ifdef HEXDUMP
    hexdump(stderr, data, len);
#endif
    funlockfile(stderr);
}

/**
 * ARP 応答の送信
 * @param [in,out] iface
 * @param [in] tha
 * @param [in] tpa
 * @param [in] dst
 * @return
 */
static int
arp_reply(struct net_iface *iface, const uint8_t *tha, ip_addr_t tpa, const uint8_t *dst)
{
    struct arp_ether_ip reply;

    /* Exercise13-3: ARP 応答メッセージの生成 */
    /* ※ host to network に変換が必要 */
    reply.hdr.hrd = hton16(ARP_HDR_ETHER);
    reply.hdr.pro = hton16(ARP_PRO_IP);
    reply.hdr.hln = ETHER_ADDR_LEN;
    reply.hdr.pln = IP_ADDR_LEN;
    reply.hdr.op = hton16(ARP_OP_REPLY);
    /* - spa/sha ･･･ インターフェースの IP アドレスと紐づくデバイスの MAC アドレスを設定する */
    memcpy(reply.sha, iface->dev->addr, ETHER_ADDR_LEN);
    memcpy(reply.spa, &((struct ip_iface *)iface)->unicast, IP_ADDR_LEN);
    /* - tpa/tha ･･･ ARP 要求を送ってきたノードの IP アドレスと MAC アドレスを設定する */
    memcpy(reply.tha, tha, ETHER_ADDR_LEN);
    memcpy(reply.tpa, &tpa, IP_ADDR_LEN);

    debugf("dev=%s, len=%zu", iface->dev->name, sizeof(reply));
    arp_dump((uint8_t *)&reply, sizeof(reply));
    /* デバイスから ARP メッセージを送信 */
    return net_device_output(iface->dev, ETHER_TYPE_ARP, (uint8_t *)&reply, sizeof(reply), dst);
}

/**
 * ARP メッセージの受信
 * @param [in] data データポインタ
 * @param [in] len データ長
 * @param [in,out] dev デバイス構造体ポインタ
 */
static void
arp_input(const uint8_t *data, size_t len, struct net_device *dev)
{
    struct arp_ether_ip *msg;
    ip_addr_t spa, tpa;
    struct net_iface *iface;

    /* 期待する ARP メッセージのサイズより小さかったらエラーを返す */
    if (len < sizeof(*msg)) {
        errorf("too short");
        return;
    }
    msg = (struct arp_ether_ip *)data;

    /* Exercise13-1: 対応可能なアドレスペアのメッセージのみ受け入れる */
    /* (1) ハードウェアアドレスのチェック */
    /* - アドレス種別とアドレス長が Ethernet と合致しなければ中断 */
    if (ntoh16(msg->hdr.hrd) != ARP_HDR_ETHER || msg->hdr.hln != ETHER_ADDR_LEN) {
        errorf("not match hardware address = ETHER");
        return;
    }
    /* (2) プロトコルアドレスのチェック */
    /* - アドレス種別とアドレス長が IP と合致しなければ中断 */
    if (ntoh16(msg->hdr.pro) != ARP_PRO_IP || msg->hdr.pln != IP_ADDR_LEN) {
        errorf("not match protocol address = IP");
        return;
    }

    debugf("dev=%s, len=%zu", dev->name, len);
    arp_dump(data, len);
    /* spa/tpa を memcpy() で ip_addr_t の変数へ取り出す */
    memcpy(&spa, msg->spa, sizeof(spa));
    memcpy(&tpa, msg->tpa, sizeof(tpa));
    /* デバイスに紐づく IP インターフェースを取得する */
    iface = net_device_get_iface(dev, NET_IFACE_FAMILY_IP);
    /* ARP 要求のターゲットプロトコルアドレスと一致するか確認 */
    if (iface && ((struct ip_iface *)iface)->unicast == tpa) {
        /* Exercise13-2: ARP要求への応答 */
        /* - メッセージ種別が ARP 要求だったら arp_reply() を呼び出して ARP 応答を送信する */
        if (ntoh16(msg->hdr.op) == ARP_OP_REQUEST) { /* ※ network to host に変換が必要 */
            /* 送信元のハードウェアアドレス(sha), 送信元プロトコルアドレス(spa), */
            /* ターゲットプロトコルアドレス(tpa) を利用して送信元に対して応答する */
            arp_reply(iface, msg->sha, spa, msg->sha);
        }
    }
}

/**
 * ARP の初期化(登録)
 */
int
arp_init(void)
{
    /* Exercise13-4: プロトコルスタックに ARP を登録する */
    if (net_protocol_register(NET_PROTOCOL_TYPE_ARP, arp_input) == -1) {
        errorf("net_protocol_register() failure");
        return -1;
    }
    return 0;
}