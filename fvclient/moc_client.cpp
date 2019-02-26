/****************************************************************************
** Meta object code from reading C++ file 'client.h'
**
** Created by: The Qt Meta Object Compiler version 67 (Qt 5.9.5)
**
** WARNING! All changes made in this file will be lost!
*****************************************************************************/

#include "client.h"
#include <QtCore/qbytearray.h>
#include <QtCore/qmetatype.h>
#if !defined(Q_MOC_OUTPUT_REVISION)
#error "The header file 'client.h' doesn't include <QObject>."
#elif Q_MOC_OUTPUT_REVISION != 67
#error "This file was generated using the moc from 5.9.5. It"
#error "cannot be used with the include files from this version of Qt."
#error "(The moc has changed too much.)"
#endif

QT_BEGIN_MOC_NAMESPACE
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
struct qt_meta_stringdata_Client_t {
    QByteArrayData data[12];
    char stringdata0[122];
};
#define QT_MOC_LITERAL(idx, ofs, len) \
    Q_STATIC_BYTE_ARRAY_DATA_HEADER_INITIALIZER_WITH_OFFSET(len, \
    qptrdiff(offsetof(qt_meta_stringdata_Client_t, stringdata0) + ofs \
        - idx * sizeof(QByteArrayData)) \
    )
static const qt_meta_stringdata_Client_t qt_meta_stringdata_Client = {
    {
QT_MOC_LITERAL(0, 0, 6), // "Client"
QT_MOC_LITERAL(1, 7, 17), // "joinServerSucceed"
QT_MOC_LITERAL(2, 25, 0), // ""
QT_MOC_LITERAL(3, 26, 6), // "userID"
QT_MOC_LITERAL(4, 33, 16), // "joinServerFailed"
QT_MOC_LITERAL(5, 50, 6), // "errMsg"
QT_MOC_LITERAL(6, 57, 11), // "newTraverse"
QT_MOC_LITERAL(7, 69, 15), // "traverseSucceed"
QT_MOC_LITERAL(8, 85, 4), // "port"
QT_MOC_LITERAL(9, 90, 14), // "traverseFailed"
QT_MOC_LITERAL(10, 105, 11), // "disconneted"
QT_MOC_LITERAL(11, 117, 4) // "stop"

    },
    "Client\0joinServerSucceed\0\0userID\0"
    "joinServerFailed\0errMsg\0newTraverse\0"
    "traverseSucceed\0port\0traverseFailed\0"
    "disconneted\0stop"
};
#undef QT_MOC_LITERAL

static const uint qt_meta_data_Client[] = {

 // content:
       7,       // revision
       0,       // classname
       0,    0, // classinfo
       7,   14, // methods
       0,    0, // properties
       0,    0, // enums/sets
       0,    0, // constructors
       0,       // flags
       7,       // signalCount

 // signals: name, argc, parameters, tag, flags
       1,    1,   49,    2, 0x06 /* Public */,
       4,    1,   52,    2, 0x06 /* Public */,
       6,    0,   55,    2, 0x06 /* Public */,
       7,    2,   56,    2, 0x06 /* Public */,
       9,    2,   61,    2, 0x06 /* Public */,
      10,    0,   66,    2, 0x06 /* Public */,
      11,    0,   67,    2, 0x06 /* Public */,

 // signals: parameters
    QMetaType::Void, QMetaType::QString,    3,
    QMetaType::Void, QMetaType::QString,    5,
    QMetaType::Void,
    QMetaType::Void, QMetaType::QString, QMetaType::UShort,    3,    8,
    QMetaType::Void, QMetaType::QString, QMetaType::QString,    3,    5,
    QMetaType::Void,
    QMetaType::Void,

       0        // eod
};

void Client::qt_static_metacall(QObject *_o, QMetaObject::Call _c, int _id, void **_a)
{
    if (_c == QMetaObject::InvokeMetaMethod) {
        Client *_t = static_cast<Client *>(_o);
        Q_UNUSED(_t)
        switch (_id) {
        case 0: _t->joinServerSucceed((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 1: _t->joinServerFailed((*reinterpret_cast< QString(*)>(_a[1]))); break;
        case 2: _t->newTraverse(); break;
        case 3: _t->traverseSucceed((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< quint16(*)>(_a[2]))); break;
        case 4: _t->traverseFailed((*reinterpret_cast< QString(*)>(_a[1])),(*reinterpret_cast< QString(*)>(_a[2]))); break;
        case 5: _t->disconneted(); break;
        case 6: _t->stop(); break;
        default: ;
        }
    } else if (_c == QMetaObject::IndexOfMethod) {
        int *result = reinterpret_cast<int *>(_a[0]);
        {
            typedef void (Client::*_t)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::joinServerSucceed)) {
                *result = 0;
                return;
            }
        }
        {
            typedef void (Client::*_t)(QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::joinServerFailed)) {
                *result = 1;
                return;
            }
        }
        {
            typedef void (Client::*_t)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::newTraverse)) {
                *result = 2;
                return;
            }
        }
        {
            typedef void (Client::*_t)(QString , quint16 );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::traverseSucceed)) {
                *result = 3;
                return;
            }
        }
        {
            typedef void (Client::*_t)(QString , QString );
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::traverseFailed)) {
                *result = 4;
                return;
            }
        }
        {
            typedef void (Client::*_t)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::disconneted)) {
                *result = 5;
                return;
            }
        }
        {
            typedef void (Client::*_t)();
            if (*reinterpret_cast<_t *>(_a[1]) == static_cast<_t>(&Client::stop)) {
                *result = 6;
                return;
            }
        }
    }
}

const QMetaObject Client::staticMetaObject = {
    { &QThread::staticMetaObject, qt_meta_stringdata_Client.data,
      qt_meta_data_Client,  qt_static_metacall, nullptr, nullptr}
};


const QMetaObject *Client::metaObject() const
{
    return QObject::d_ptr->metaObject ? QObject::d_ptr->dynamicMetaObject() : &staticMetaObject;
}

void *Client::qt_metacast(const char *_clname)
{
    if (!_clname) return nullptr;
    if (!strcmp(_clname, qt_meta_stringdata_Client.stringdata0))
        return static_cast<void*>(this);
    return QThread::qt_metacast(_clname);
}

int Client::qt_metacall(QMetaObject::Call _c, int _id, void **_a)
{
    _id = QThread::qt_metacall(_c, _id, _a);
    if (_id < 0)
        return _id;
    if (_c == QMetaObject::InvokeMetaMethod) {
        if (_id < 7)
            qt_static_metacall(this, _c, _id, _a);
        _id -= 7;
    } else if (_c == QMetaObject::RegisterMethodArgumentMetaType) {
        if (_id < 7)
            *reinterpret_cast<int*>(_a[0]) = -1;
        _id -= 7;
    }
    return _id;
}

// SIGNAL 0
void Client::joinServerSucceed(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 0, _a);
}

// SIGNAL 1
void Client::joinServerFailed(QString _t1)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)) };
    QMetaObject::activate(this, &staticMetaObject, 1, _a);
}

// SIGNAL 2
void Client::newTraverse()
{
    QMetaObject::activate(this, &staticMetaObject, 2, nullptr);
}

// SIGNAL 3
void Client::traverseSucceed(QString _t1, quint16 _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 3, _a);
}

// SIGNAL 4
void Client::traverseFailed(QString _t1, QString _t2)
{
    void *_a[] = { nullptr, const_cast<void*>(reinterpret_cast<const void*>(&_t1)), const_cast<void*>(reinterpret_cast<const void*>(&_t2)) };
    QMetaObject::activate(this, &staticMetaObject, 4, _a);
}

// SIGNAL 5
void Client::disconneted()
{
    QMetaObject::activate(this, &staticMetaObject, 5, nullptr);
}

// SIGNAL 6
void Client::stop()
{
    QMetaObject::activate(this, &staticMetaObject, 6, nullptr);
}
QT_WARNING_POP
QT_END_MOC_NAMESPACE
