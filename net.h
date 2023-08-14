#ifndef NET_H
#define NET_H

#include <stddef.h>
#include <stdint.h>

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

#define NET_DEVICE_TYPE_DUMMY       0x0000
#define NET_DEVICE_TYPE_LOOPBACK    0x0001
#define NET_DEVICE_TYPE_ETHERNET    0x0002

#define NET_DEVICE_FLAG_UP          0x0001
#define NET_DEVICE_FLAG_LOOPBACK    0x0010
#define NET_DEVICE_FLAG_BROADCAST   0x0020
#define NET_DEVICE_FLAG_P2P         0x0040
#define NET_DEVICE_FLAG_NEED_ARP    0x0100

#define NET_DEVICE_ADDR_LEN 16

#define NET_DEVICE_IS_UP(x) ((x)->flags & NET_DEVICE_FLAG_UP)
#define NET_DEVICE_STATE(x) (NET_DEVICE_IS_UP(x) ? "up" : "down")

/* NOTE: use same value as the Ethernet types */
#define NET_PROTOCOL_TYPE_IP    0x0800
#define NET_PROTOCOL_TYPE_ARP   0x0806
#define NET_PROTOCOL_TYPE_IPV6  0x86dd

/* インターフェースの種別 (ファミリ) の値 */
#define NET_IFACE_FAMILY_IP     1
#define NET_IFACE_FAMILY_IPV6   2

#define NET_IFACE(x) ((struct net_iface *)(x))

/**
 * デバイス構造体
*/
struct net_device {
    /* 次のデバイスへのポインタ */
    struct net_device *next;

    /* インターフェースリスト */
    struct net_iface *ifaces; /* NOTE: if you want to add/delete the entries after net_run(), you need to protect ifaces with a mutex. */

    unsigned int index;
    char name[IFNAMSIZ];
    /* デバイスの種別(NET_DEVICE_TYPE_XXX) */
    uint16_t type;
    
    /* デバイスの種類によって変化する値 */
    /* デバイスのMTU(Maximum Transmission Unit)の値 */
    uint16_t mtu;
    /* 各種フラグ(NET_DEVICE_FLAG_XXX) */
    uint16_t flags;
    /* header length */
    uint16_t hlen;
    /* address length */
    uint16_t alen;
    
    /* デバイスのハードウェアアドレス等 */
    uint8_t addr[NET_DEVICE_ADDR_LEN];
    union {
        uint8_t peer[NET_DEVICE_ADDR_LEN];
        uint8_t broadcast[NET_DEVICE_ADDR_LEN];
    };

    /* デバイスドライバに実装されている関数が設定された struct net_device_ops へのポインタ */
    struct net_device_ops *ops;
    /* デバイスドライバが使うプライベートなデータへのポインタ */
    void *priv;
};

/**
 * デバイスドライバに実装されている関数へのポインタを格納
*/
struct net_device_ops {
    /* オープン関数(任意) */
    int (*open)(struct net_device *dev);
    /* クローズ関数(任意) */
    int (*close)(struct net_device *dev);
    /* 送信関数(必須) */
    int (*transmit)(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);
};

/**
 * インターフェース構造体
 * ※抽象的なインターフェース構造体
 * （デバイスにインターフェースを紐づける仕組みだけ）
*/
struct net_iface {
    /* 次のインターフェースへのポインタ */
    struct net_iface *next;

    /* インターフェースが紐づけられているデバイスへのポインタ */
    struct net_device *dev; /* back pointer to parent */

    /* 具体的なインターフェースの種別 */
    int family;
    /* depends on implementation of protocols */
};

extern struct net_device *
net_device_alloc(void);

/**
 * デバイスの登録
*/
extern int
net_device_register(struct net_device *dev);

extern int
net_device_add_iface(struct net_device *dev, struct net_iface *iface);

extern struct net_iface *
net_device_get_iface(struct net_device *dev, int family);

/**
 * デバイスへの出力
*/
extern int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

/**
 * プロトコルの登録
*/
extern int
net_protocol_register(uint16_t type, void (*handler)(const uint8_t *data, size_t len, struct net_device *dev));

/**
 * デバイスが受信したパケットをプロトコルスタックに渡す
 * - プロトコルスタックへのデータの入口であり、デバイスドライバから呼び出されることを想定
*/
extern int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);

/**
 * ソフトウェア割り込みハンドラ
*/
extern int
net_softirq_handler(void);

/**
 * プロトコルスタックの起動
*/
extern int
net_run(void);

/**
 * プロトコルスタックの停止
 */
extern void
net_shutdown(void);

/**
 * プロトコルスタックの初期化
*/
extern int
net_init(void);

#endif