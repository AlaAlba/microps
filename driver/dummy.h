#ifndef DUMMY_H
#define DUMMY_H

#include "net.h"

/**
 * ダミーデバイスの初期化
 */
extern struct net_device *
dummy_init(void);

#endif