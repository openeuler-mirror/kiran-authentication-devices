/**
 * Copyright (c) 2020 ~ 2021 KylinSec Co., Ltd.
 * kiran-authentication-devices is licensed under Mulan PSL v2.
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
#include <QSqlDatabase>
#include <QSqlQuery>
#include "auth-enum.h"
#include "kiran-auth-device-i.h"

namespace Kiran
{
struct FeatureInfo
{
    QString id;
    QString idVendor;
    QString idProduct;
    int deviceType;
    QString deviceSerialNumber;
};

class FeatureDB
{
public:
    explicit FeatureDB();
    ~FeatureDB();

    static FeatureDB *getInstance() { return m_instance; };
    static void globalInit();
    static void globalDeinit() { delete m_instance; };

    bool createDBConnection();
    bool addFeature(const QString &featureID, QByteArray feature,
                    DeviceInfo deviceInfo, DeviceType deviceType,
                    const QString &deviceSerialNumber = QString());
    bool deleteFeature(const QString &featureID);

    QByteArray getFeature(const QString &featureID);
    QList<QByteArray> getFeatures(const QString &idVendor, const QString &idProduct, DeviceType deviceType, const QString &deviceSerialNumber);
    QList<QByteArray> getAllFeatures();
    QStringList getFeatureIDs(const QString &idVendor, const QString &idProduct, DeviceType deviceType, const QString &deviceSerialNumber);
    QString getFeatureID(QByteArray feature);
    QStringList getAllFeatureIDs();
    FeatureInfo getFeatureInfo(const QString &featureID);

    bool updateFeature(const QString &featureID, QByteArray newFeature);

    bool contains(const QString &featureID);

private:
    void init();

private:
    QSqlDatabase m_database;
    static FeatureDB *m_instance;
};
}  // namespace Kiran
