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

/**
 * デバイス構造体
*/
struct net_device {
    /* 次のデバイスへのポインタ */
    struct net_device *next;

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

extern struct net_device *
net_device_alloc(void);

/**
 * デバイスの登録
*/
extern int
net_device_register(struct net_device *dev);

/**
 * デバイスへの出力
*/
extern int
net_device_output(struct net_device *dev, uint16_t type, const uint8_t *data, size_t len, const void *dst);

/**
 * デバイスが受信したパケットをプロトコルスタックに渡す
 * - プロトコルスタックへのデータの入口であり、デバイスドライバから呼び出されることを想定
*/
extern int
net_input_handler(uint16_t type, const uint8_t *data, size_t len, struct net_device *dev);

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