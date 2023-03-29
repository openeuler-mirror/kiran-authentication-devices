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

#include <qt5-log-i.h>
#include <QCoreApplication>
#include <QTranslator>
#include "auth-device-manager.h"
#include "feature-db.h"
#include "config.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    klog_qt5_init("", "kylinsec-system", "kiran-authentication-devices", "kiran-authentication-devices");
    QTranslator translator;
    if (translator.load(QLocale(), qAppName(), ".", TRANSLATE_PREFIX, ".qm"))
    {
        a.installTranslator(&translator);
    }
    else
    {
        KLOG_WARNING() << "Load translator failed!";
    }

    Kiran::FeatureDB::globalInit();
    Kiran::AuthDeviceManager::globalInit();

    auto retval = a.exec();

    Kiran::AuthDeviceManager::globalDeint();
    Kiran::FeatureDB::globalDeinit();
    return retval;
}
