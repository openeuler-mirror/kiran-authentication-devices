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

#include <QObject>
#include <QSharedPointer>
#include <functional>
#include "context.h"

namespace Kiran
{
class ContextFactory : public QObject
{
    Q_OBJECT

private:
    explicit ContextFactory(QObject* parent = nullptr);

public:
    static ContextFactory* getInstance();

    AuthDevicePtr createDevice(const QString& idVendor, const QString& idProduct);

    bool isDeviceSupported(const QString& idVendor, const QString& idProduct);
    void DestoryContext(Context* context);

    void registerContext(std::function<Context*()>);
    void createContext();

private:
    QStringList m_idVendorList;
    QList<QSharedPointer<Context>> m_contexts;
    QList<std::function<Context*()>> m_listContextFunc;
};

class ContextRegisterHelper
{
public:
    ContextRegisterHelper(std::function<Context*()> func)
    {
        ContextFactory::getInstance()->registerContext(func);
    }
};

/**
 * 定义全局静态变量，利用全局静态变量在进程开始时创建（在main函数之前初始化）
 * 将所有context子类构造函数注册到contextFactory单例对象中
*/
#define REGISTER_CONTEXT(className) \
    static ContextRegisterHelper className##ObjectRegisterHelper([]() -> className* { return new className(); })

}  // namespace Kiran
