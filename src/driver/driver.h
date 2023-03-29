/**
 * Copyright (c) 2020 ~ 2021 KylinSec Co., Ltd.
 * kiran-biometrics is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author:     luoqing <luoqing@kylinsec.com.cn>
 */
#pragma once

#include <QObject>

namespace Kiran
{
class BDriver : public QObject
{
    Q_OBJECT
public:
    explicit BDriver(QObject *parent = nullptr);
    virtual ~BDriver(){};
    virtual QString getName() = 0;
    virtual QString getFullName() = 0;
    virtual quint16 getDriverId() = 0;

Q_SIGNALS:
};
}  // namespace Kiran
