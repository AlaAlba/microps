#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#include "util.h"
#include "net.h"
#include "ip.h"

#include "driver/loopback.h"

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

int
main(int argc, char *argv[])
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

    /* プロトコルスタックの起動 */
    if (net_run() == -1) {
        errorf("net_run() failure");
        return -1;
    }

    /* Ctrl+C が押されるとシグナルハンドラ on_signal() の中で terminate に1が設定される */
    while (!terminate) {
        /* 1秒おきにデバイスにパケットを書き込む */
        if (net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data, sizeof(test_data), NULL) == -1) {
            errorf("net_device_output() failure");
            break;
        }
        sleep(1);
    }

    /* プロトコルスタックの停止 */
    net_shutdown();
    return 0;
}