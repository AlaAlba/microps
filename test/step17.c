#include <stdio.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"
#include "icmp.h"

#include "driver/loopback.h"
#include "driver/ether_tap.h"

#include "test.h"

static volatile sig_atomic_t terminate;

static void
on_signal(int s)
{
    /**
     * 原則、シグナルハンドラの中では下記以外の事をしない
        ・非同期シグナル安全な関数の呼び出し
        https://www.jpcert.or.jp/sc-rules/c-sig30-c.html
        ・volatile sig_atomic_t 型の変数への書込み
    */
    (void)s;
    terminate = 1;
}

/**
 * セットアップ(プロトコルスタックの初期化〜デバイス登録〜起動まで)
 */
static int
setup(void)
{
    struct net_device *dev;
    struct ip_iface *iface;

    /* シグナルハンドラの設定 (Ctrl+Cが押された際に行儀よく終了するように) */
    signal(SIGINT, on_signal);

    /* プロトコルスタックの初期化 */
    if (net_init() == -1) {
        errorf("net_init() failure");
        return -1;
    }

    /* ループバックデバイスの初期化 */
    /* デバイスドライバがプロトコルスタックへの登録まで済ませる */
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failure");
        return -1;
    }

    /* IPアドレスとサブネットマスクを指定してIPインターフェースを生成 */
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    /* IPインターフェースの登録 (dev に iface が紐づけられる) */
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failure");
        return -1;
    }

    /* Ethernet デバイスの生成 */
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failure");
        return -1;
    }
    /* IPインターフェースを生成して紐づける */
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failure");
        return -1;
    }
    if (ip_iface_register(dev, iface) == -1) {
        errorf("ip_iface_register() failrue");
        return -1;
    }

    /* デフォルトゲートウェイを登録 (192.0.2.1) */
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) == -1) {
        errorf("ip_route_set_default_gateway() failure");
        return -1;
    }

    /* プロトコルスタックの起動 */
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }
    return 0;
}

/**
 * クリーンアップ
 */
static void
cleanup(void)
{
    /* プロトコルスタックの停止 */
    net_shutdown();
}

int
main(int argc, char *argv[])
{
    ip_addr_t src, dst;
    uint16_t id, seq = 0;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;

    /* プロトコルスタックの初期化〜デバイス登録〜起動までのセットアップ */
    if (setup() == -1) {
        errorf("setup() failure");
        return -1;
    }
    
    src = IP_ADDR_ANY; /* 送信元アドレスは明示的に指定しない */
    ip_addr_pton("8.8.8.8", &dst); /* 宛先アドレスをインターネット上のノードのIPアドレスにする */
    id = getpid() % UINT16_MAX;

    /* Ctrl+C が押されるとシグナルハンドラ on_signal() の中で terminate に1が設定される */
    while (!terminate) {
        
        if (icmp_output(ICMP_TYPE_ECHO, 0, hton32(id << 16 | ++seq), test_data + offset, sizeof(test_data) - offset, src, dst) == -1) {
            errorf("icmp_output() failure");
            break;
        }
        
        sleep(1);
    }
    cleanup();
    return 0;
}