#include <stdint.h>
#include <stddef.h>

#include "util.h"
#include "ip.h"
#include "icmp.h"

/**
 * ICMP の入力関数
 * @param [in] data データポインタ
 * @param [in] len データサイズ
 * @param [in] src 送信元IPアドレス
 * @param [in] dst 宛先IPアドレス
 * @param [in,out] iface IPインターフェース
 */
void
icmp_input(const uint8_t *data, size_t len, ip_addr_t src, ip_addr_t dst, struct ip_iface *iface)
{
    char addr1[IP_ADDR_STR_LEN];
    char addr2[IP_ADDR_STR_LEN];

    /* このステップでは登録した入力関数が呼び出されたことが分かればいいのでデバッグ出力のみ */
    debugf("%s => %s, len=%zu", ip_addr_ntop(src, addr1, sizeof(addr1)), ip_addr_ntop(dst, addr2, sizeof(addr2)), len);
    debugdump(data, len);
}

/**
 * ICMP の初期化
 * ICMP の入力関数を IP に登録
 */
int
icmp_init(void)
{
    /* Exercise9-4: ICMP の入力関数 (icmp_input) を IP に登録 */
    /* - プロトコル番号は ip.h に定義してある定数を使う */
    if (ip_protocol_register(IP_PROTOCOL_ICMP, icmp_input) == -1) {
        errorf("ip_protocol_register() failure");
        return -1;
    }
    return 0;
}
