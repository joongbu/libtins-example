QT      += core gui sql
INCLUDEPATH += /usr/include/mysql
LIBS += -L/usr/lib/mysql -lmysqlclient_r
TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -ltins
LIBS += -lpthread
SOURCES += main.cpp

HEADERS +=
