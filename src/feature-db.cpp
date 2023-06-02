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

#include "feature-db.h"
#include <qt5-log-i.h>
#include <QDir>
#include <QSqlError>

namespace Kiran
{
FeatureDB::FeatureDB()
{
}

FeatureDB::~FeatureDB()
{
    if (m_database.isValid())
    {
        if (m_database.isOpen())
            m_database.close();
    }
}

FeatureDB *FeatureDB::m_instance = nullptr;
void FeatureDB::globalInit()
{
    m_instance = new FeatureDB();
    m_instance->init();
}

void FeatureDB::init()
{
    createDBConnection();
}

bool FeatureDB::createDBConnection()
{
    if (QSqlDatabase::contains("qt_sql_default_connection"))
    {
        m_database = QSqlDatabase::database("qt_sql_default_connection");
    }
    else
    {
        QDir dir(DATABASE_DIR);
        if (!dir.exists())
        {
            dir.mkpath(DATABASE_DIR);
        }
        QString dbPath = QString("%1/FeatureDataBase.db").arg(DATABASE_DIR);
        m_database = QSqlDatabase::addDatabase("QSQLITE");
        m_database.setDatabaseName(dbPath);
        if (!m_database.open())
        {
            KLOG_ERROR() << "Failed to connect database:" << m_database.lastError();
            return false;
        }

        QSqlQuery query(m_database);
        QString createTable = QString("CREATE TABLE IF NOT EXISTS [feature]("
                                      "featureID TEXT PRIMARY KEY NOT NULL,"
                                      "feature BLOB NOT NULL,"
                                      "idVendor TEXT,"
                                      "idProduct TEXT,"
                                      "deviceType INT,"
                                      "deviceSerialNumber TEXT);");

        if (!query.exec(createTable))
        {
            KLOG_DEBUG() << "query.lastError():" << query.lastError();
        }
    }
    return true;
}

bool FeatureDB::addFeature(const QString &featureID, QByteArray feature, DeviceInfo deviceInfo, DeviceType deviceType, const QString &deviceSerialNumber)
{
    QSqlQuery query(m_database);
    query.prepare("INSERT into feature(featureID, feature, idVendor, idProduct, deviceType, deviceSerialNumber) VALUES(:featureID, :feature,:idVendor, :idProduct, :deviceType, :deviceSerialNumber) ;");
    query.bindValue(":featureID", featureID);
    query.bindValue(":feature", feature);
    query.bindValue(":idVendor", deviceInfo.idVendor);
    query.bindValue(":idProduct", deviceInfo.idProduct);
    query.bindValue(":deviceType", (int)deviceType);
    query.bindValue(":deviceSerialNumber", deviceSerialNumber);
    return query.exec();
}

bool FeatureDB::deleteFeature(const QString &featureID)
{
    QSqlQuery query(m_database);
    query.prepare("DELETE FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    return query.exec();
}

QByteArray FeatureDB::getFeature(const QString &featureID)
{
    QSqlQuery query(m_database);
    query.prepare("SELECT feature  FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    query.exec();
    if (query.next())
    {
        QByteArray feature = query.value(0).toByteArray();
        return feature;
    }
    return QByteArray();
}

QList<QByteArray> FeatureDB::getFeatures(const QString &idVendor, const QString &idProduct, DeviceType deviceType, const QString &deviceSerialNumber)
{
    QSqlQuery query(m_database);
    query.prepare("SELECT feature  FROM feature WHERE idVendor = :Vid AND idProduct = :Pid AND deviceType = :devType AND deviceSerialNumber = :serialNumber");
    query.bindValue(":Vid", idVendor);
    query.bindValue(":Pid", idProduct);
    query.bindValue(":devType", (int)deviceType);
    query.bindValue(":serialNumber", deviceSerialNumber);
    query.exec();
    QByteArrayList featuresList;
    while (query.next())
    {
        QByteArray feature = query.value(0).toByteArray();
        featuresList << feature;
    }
    return featuresList;
}

QList<QByteArray> FeatureDB::getAllFeatures()
{
    QSqlQuery query(m_database);
    query.prepare("SELECT feature FROM feature");
    query.exec();
    QByteArrayList featuresList;
    while (query.next())
    {
        QByteArray feature = query.value(0).toByteArray();
        featuresList << feature;
    }
    return featuresList;
}

QStringList FeatureDB::getFeatureIDs(const QString &idVendor, const QString &idProduct, DeviceType deviceType, const QString &deviceSerialNumber)
{
    QSqlQuery query(m_database);
    query.prepare("SELECT featureID  FROM feature WHERE idVendor = :Vid AND idProduct = :Pid AND deviceType = :devType AND deviceSerialNumber = :serialNumber");
    query.bindValue(":Vid", idVendor);
    query.bindValue(":Pid", idProduct);
    query.bindValue(":devType", (int)deviceType);
    query.bindValue(":serialNumber", deviceSerialNumber);
    query.exec();
    QStringList featureIDs;
    while (query.next())
    {
        QString featureID = query.value(0).toString();
        featureIDs << featureID;
    }
    return featureIDs;
}

QString FeatureDB::getFeatureID(QByteArray feature)
{
    QSqlQuery query(m_database);
    query.prepare("SELECT featureID  FROM feature WHERE feature = :feature");
    query.bindValue(":feature", feature);
    query.exec();
    if (query.next())
    {
        QString featureID = query.value(0).toString();
        return featureID;
    }
    return QString();
}

QStringList FeatureDB::getAllFeatureIDs()
{
    QSqlQuery query(m_database);
    query.prepare("SELECT featureID  FROM feature");
    query.exec();
    QStringList featureIDs;
    while (query.next())
    {
        QString featureID = query.value(0).toString();
        featureIDs << featureID;
    }
    return featureIDs;
}

FeatureInfo FeatureDB::getFeatureInfo(const QString &featureID)
{
    QSqlQuery query(m_database);
    query.prepare("SELECT idVendor, idProduct, deviceType, deviceSerialNumber FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    query.exec();
    FeatureInfo featureInfo;
    if (query.next())
    {
        featureInfo.id = featureID;
        featureInfo.idVendor = query.value("idVendor").toString();
        featureInfo.idProduct = query.value("idProduct").toString();
        featureInfo.deviceType = query.value("deviceType").toInt();
        featureInfo.deviceSerialNumber = query.value("deviceSerialNumber").toString();
    }
    return featureInfo;
}

bool FeatureDB::updateFeature(const QString &featureID, QByteArray newFeature)
{
    QSqlQuery query(m_database);
    query.prepare("UPDATE feature  SET feature = :feature WHERE featureID = :featureID ");
    query.bindValue(":feature", newFeature);
    query.bindValue(":featureID", featureID);
    return query.exec();
}

bool FeatureDB::contains(const QString &featureID)
{
    QSqlQuery query(m_database);
    query.prepare("SELECT featureID  FROM feature WHERE featureID = :id");
    query.bindValue(":id", featureID);
    query.exec();
    if (query.next())
    {
        return true;
    }
    else
    {
        return false;
    }
}

}  // namespace Kiran
