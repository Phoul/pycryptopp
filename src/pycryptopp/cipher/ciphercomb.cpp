/**
* ciphercomb.cpp -- Python wrappers around Crypto++'s AES-CTR and XSalsa20
*/

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#if (PY_VERSION_HEX < 0x02050000)
typedef int Py_ssize_t;
#endif

#include "ciphercomb.hpp"
#include <iostream>
/* from Crypto++ */
#ifdef USE_NAME_CRYPTO_PLUS_PLUS
#include <cryptopp/modes.h>
#include <cryptopp/aes.h>
#include <cryptopp/salsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#else
#include <src-cryptopp/modes.h>
#include <src-cryptopp/aes.h>
#include <src-cryptopp/salsa.h>
#include <src-cryptopp/sha.h>
#include <src-cryptopp/hmac.h>
#endif
using namespace std;

static const char*const ciphercomb___doc__ = "_ciphercomb mode\n\
You are advised to run aes.start_up_self_test() after importing this module.";

static PyObject *ciphercomb_error;

typedef struct {
    PyObject_HEAD

    /* internal */
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption * e1;
    CryptoPP::XSalsa20::Encryption *e2;
} CipherComb;

PyDoc_STRVAR(CipherComb__doc__,
"A CipherComb cipher object.\n\
\n\
This object encrypts/decrypts in Combiner mode.\n\
\n\
");

static PyObject *
CipherComb_process(CipherComb* self, PyObject* msgobj) {
    if (!PyString_CheckExact(msgobj)) {
        PyStringObject* typerepr = reinterpret_cast<PyStringObject*>(PyObject_Repr(reinterpret_cast<PyObject*>(msgobj->ob_type)));
        if (typerepr) {
            PyErr_Format(ciphercomb_error, "Precondition violation: you are required to pass a Python string object (not a unicode, a subclass of string, or anything else), but you passed %s.", PyString_AS_STRING(reinterpret_cast<PyObject*>(typerepr)));
            Py_DECREF(typerepr);
        } else
            PyErr_Format(ciphercomb_error, "Precondition violation: you are required to pass a Python string object (not a unicode, a subclass of string, or anything else).");
        return NULL;
    }

    const char *msg;
    Py_ssize_t msgsize;
    if (PyString_AsStringAndSize(msgobj, const_cast<char**>(&msg), &msgsize))
        return NULL;
    assert (msgsize >= 0);

    PyStringObject* result1 = reinterpret_cast<PyStringObject*>(PyString_FromStringAndSize(NULL, msgsize));
    if (!result1)
        return NULL;

    self->e1->ProcessData(reinterpret_cast<byte*>(PyString_AS_STRING(result1)), reinterpret_cast<const byte*>(msg), msgsize);

    PyStringObject* result2 = reinterpret_cast<PyStringObject*>(PyString_FromStringAndSize(NULL, msgsize));
    if (!result2)
        return NULL;
    self->e2->ProcessString(reinterpret_cast<byte*>(PyString_AS_STRING(result2)), reinterpret_cast<const byte*>(PyString_AS_STRING(result1)), msgsize);
    
    return reinterpret_cast<PyObject*>(result2);
}

PyDoc_STRVAR(CipherComb_process__doc__,
        "Encrypt or decrypt the next bytes, returning the result.");

static PyMethodDef CipherComb_methods[] = {
    {"process", reinterpret_cast<PyCFunction>(CipherComb_process), METH_O, CipherComb_process__doc__},
    {NULL},
};

static PyObject *
CipherComb_new(PyTypeObject* type, PyObject *args, PyObject *kwdict) {
    CipherComb* self = reinterpret_cast<CipherComb*>(type->tp_alloc(type, 0));
    if (!self)
        return NULL;
    self->e1 = NULL;
    self->e2 = NULL;
    return reinterpret_cast<PyObject*>(self);
}

static void
CipherComb_dealloc(PyObject* self) {
    if (reinterpret_cast<CipherComb*>(self)->e1)
        delete reinterpret_cast<CipherComb*>(self)->e1;
    if (reinterpret_cast<CipherComb*>(self)->e2)
        delete reinterpret_cast<CipherComb*>(self)->e2;
    self->ob_type->tp_free(self);
}

static int
CipherComb_init(PyObject* self, PyObject *args, PyObject *kwdict) {
    static const char *kwlist[] = { "key", "iv", NULL };
    const char *key = NULL;
    Py_ssize_t keysize = 0;
    const char *iv = NULL;
    const char defaultiv[40] = {0};
    Py_ssize_t ivsize = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwdict, "t#|t#:CipherComb.__init__", const_cast<char**>(kwlist), &key, &keysize, &iv, &ivsize))
        return -1;
    assert (keysize >= 0);
    assert (ivsize >= 0);

    char prk[32];
    char* salt="";
    CryptoPP::HMAC<CryptoPP::SHA256>(reinterpret_cast<byte*>(salt), 0).CalculateDigest(reinterpret_cast<byte*>(prk), reinterpret_cast<const byte*>(key), keysize);

    char t1[32];
    char t2[32];
    char ext1[1] = {0x01};
    CryptoPP::HMAC<CryptoPP::SHA256>(reinterpret_cast<byte*>(prk), 32).CalculateDigest(reinterpret_cast<byte*>(t1), reinterpret_cast<const byte*>(ext1), 1);
    char ext2[33];
    memcpy(ext2, t1, 32);
    ext2[32] = 0x02;
    CryptoPP::HMAC<CryptoPP::SHA256>(reinterpret_cast<byte*>(prk), 32).CalculateDigest(reinterpret_cast<byte*>(t2), reinterpret_cast<const byte*>(ext2), 33);

    char aeskey[16];
    int aeskeysize = 16;
    char xsalsakey[32];
    int xskeysize = 32;
    memcpy(aeskey, t1, 16);
    memcpy(xsalsakey, t1+16, 16);
    memcpy(xsalsakey+16, t2, 16);
    
    char aesiv[16];
    char xsalsaiv[24];
    if (!iv)
        iv = defaultiv;
    memcpy(aesiv, iv, 16);
    memcpy(xsalsaiv, iv+16, 24);
    try {
        reinterpret_cast<CipherComb*>(self)->e1 = new CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(reinterpret_cast<const byte*>(aeskey), aeskeysize, reinterpret_cast<const byte*>(aesiv));
        reinterpret_cast<CipherComb*>(self)->e2 = new CryptoPP::XSalsa20::Encryption(reinterpret_cast<const byte*>(xsalsakey), xskeysize, reinterpret_cast<const byte*>(xsalsaiv));
        
    } catch (CryptoPP::InvalidKeyLength le) {
        PyErr_Format(ciphercomb_error, "Precondition violation: you are required to pass a valid key size.  Crypto++ gave this exception: %s", le.what());
        return -1;
    }
    if (!reinterpret_cast<CipherComb*>(self)->e1 || !reinterpret_cast<CipherComb*>(self)->e2 ) {
        PyErr_NoMemory();
        return -1;
    }
    return 0;
}

static PyTypeObject CipherComb_type = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_ciphercomb.CipherComb", /*tp_name*/
    sizeof(CipherComb),             /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    CipherComb_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
    CipherComb__doc__,           /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    CipherComb_methods,      /* tp_methods */
    0,                         /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    CipherComb_init,               /* tp_init */
    0,                         /* tp_alloc */
    CipherComb_new,                /* tp_new */
};

void init_ciphercomb(PyObject*const module) {
    if (PyType_Ready(&CipherComb_type) < 0)
        return;
    Py_INCREF(&CipherComb_type);
    PyModule_AddObject(module, "ciphercomb_CipherComb", (PyObject *)&CipherComb_type);

    ciphercomb_error = PyErr_NewException(const_cast<char*>("_ciphercomb.Error"), NULL, NULL);
    PyModule_AddObject(module, "ciphercomb_Error", ciphercomb_error);

    PyModule_AddStringConstant(module, "ciphercomb___doc__", const_cast<char*>(ciphercomb___doc__));
}


