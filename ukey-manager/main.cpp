/**
 * Copyright (c) 2020 ~ 2023 KylinSec Co., Ltd.
 * kiran-authentication-devices is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 * http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 * Author: luoqing <luoqing@kylinsec.com.cn>
 */
#include <qt5-log-i.h>
#include <QCommandLineParser>
#include <QCoreApplication>
#include <QTranslator>
#include <iostream>
#include "config.h"
#include "ukey-manager.h"

#define TR_SUCCESS QObject::tr("success")
#define TR_FAILED QObject::tr("failed")

void printMessage(const QString &message)
{
    KLOG_DEBUG() << message;
    std::cout << message.toStdString() << std::endl;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    klog_qt5_init("", "kylinsec-system", "kiran-authentication-devices", "kiran-ukey-manager");

    QTranslator translator;
    if (translator.load(QLocale(), qAppName(), ".", TRANSLATE_PREFIX, ".qm"))
    {
        a.installTranslator(&translator);
    }
    else
    {
        KLOG_WARNING() << "Load translator failed!";
    }

    QCommandLineOption resetOpt(QStringList() << "r" << "resetukey",QObject::tr("reset ukey"));
    QCommandLineOption changePinOpt(QStringList() << "c" << "changepin", QObject::tr("change ukey pin code"));
    QCommandLineOption unlockOpt(QStringList() << "u" << "unblock", QObject::tr("unblock pin"));
    QCommandLineOption adminPinOpt("adminpin", QObject::tr("administrator pin code"), "PINCODE", "");
    QCommandLineOption userPinOpt("userpin", QObject::tr("user Pin Code"), "PINCODE", "");
    QCommandLineOption userTypeOpt("usertype", QObject::tr("The types of users, including administrator and regular user types, correspond to admin and user."), "TYPE", "");
    QCommandLineOption currentPinOpt("currentpin", QObject::tr("current Pin Code"), "PINCODE", "");
    QCommandLineOption newPinOpt("newpin", QObject::tr("new pin code"), "PINCODE", "");

    QList<QCommandLineOption> options;
    options << resetOpt << changePinOpt << unlockOpt
            << adminPinOpt << userPinOpt
            << userTypeOpt << currentPinOpt << newPinOpt;

    QCommandLineParser parser;
    parser.setApplicationDescription(QObject::tr("Kiran Ukey Management Tool"));
    parser.addHelpOption();
    parser.addOptions(options);
    parser.process(a);

    if (!parser.isSet(resetOpt) && !parser.isSet(changePinOpt) && !parser.isSet(unlockOpt))
    {
        parser.showHelp();
    }

    ULONG ret;
    QString message;
    ULONG retryCount = 10;

    Kiran::UkeyManager ukeyManager;
    if (!ukeyManager.initDriver())
    {
        message = QObject::tr("load library failed");
        return 0;
    }

    if (parser.isSet(resetOpt))
    {
        ret = ukeyManager.resetUkey();
        message = QObject::tr("reset ukey %1").arg(ret == SAR_OK ? TR_SUCCESS : TR_FAILED);
        if (ret != SAR_OK)
        {
            message.append(ukeyManager.getErrorReason(ret));
        }
    }
    else if (parser.isSet(changePinOpt))
    {
        QString userType = parser.value(userTypeOpt);
        if ((userType != "admin") && (userType != "user"))
        {
            printMessage(QObject::tr("change pin failed,invalid user type"));
            return 0;
        }

        ret = ukeyManager.changePin(parser.value(userTypeOpt), parser.value(currentPinOpt), parser.value(newPinOpt), &retryCount);
        QString messageType;
        if (userType == "admin")
        {
            messageType = QObject::tr("admin");
        }
        else
        {
            messageType = QObject::tr("user");
        }

        message = QObject::tr("change %1 pin %2").arg(messageType).arg((ret == SAR_OK) ? TR_SUCCESS : TR_FAILED);
        if (ret != SAR_OK)
        {
            message.append(",");
            message.append(ukeyManager.getErrorReason(ret));
            message.append(QObject::tr(", remaining retry count %1").arg(retryCount));
        }
    }
    else if (parser.isSet(unlockOpt))
    {
        ret = ukeyManager.unblockPin(parser.value(adminPinOpt), parser.value(userPinOpt), &retryCount);
        message = QObject::tr("unblock pin %1").arg(ret == SAR_OK ? TR_SUCCESS : TR_FAILED);
        if (ret != SAR_OK)
        {
            message.append(",");
            message.append(ukeyManager.getErrorReason(ret));
        }
    }
    printMessage(message);

    return 0;
}
