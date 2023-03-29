#include "fp-zk-driver.h"

namespace Kiran
{
FPZKDriver::FPZKDriver(QObject *parent)
    : FPDriver{parent}
{

}

QString FPZKDriver::getName()
{
    return QString();
}

QString FPZKDriver::getFullName()
{
    return QString();
}

quint16 FPZKDriver::getDriverId()
{
    return 0;
}
}
