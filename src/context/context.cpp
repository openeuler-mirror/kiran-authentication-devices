#include "context.h"
#include "device/auth-device.h"
namespace Kiran
{
Context::Context(QObject *parent)
    : QObject{parent}
{

}

QString Context::getName()
{
    return QString();
}

AuthDevice* Context::createDevice(const QString& idVendor, const QString& idProduct)
{
    return nullptr;
}

}
