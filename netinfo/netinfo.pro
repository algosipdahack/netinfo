TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
SOURCES += \
        getmac.cpp \
        ip.cpp \
        mac.cpp \
        main.cpp

HEADERS += \
    SInterface.h \
    header.h \
    ip.h \
    mac.h
