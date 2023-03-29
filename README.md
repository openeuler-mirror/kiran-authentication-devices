# 认证设备管理
统一管理认证设备

## 编译安装
```
# yum install gcc-c++ qt5-qtbase qt5-qtbase-devel kiran-log-qt5-devel systemd-devel
# mkdir build
# cd build && cmake -DCMAKE_INSTALL_PREFIX=/usr ..
# make
# sudo make install
```

## 运行
系统启动后服务会自动启动，也可以通过手动方式启动：
```
systemctl start kiran-authentication-devices.service
```


