#define PY_SSIZE_T_CLEAN
#include <Python.h>

#include "../algorithms/SNOWV.h"

/* Python 3 initialization mess */

struct module_state
{
    PyObject *error;
};

#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))

static PyObject* error_out(PyObject *m)
{
    struct module_state *st = GETSTATE(m);
    PyErr_SetString(st->error, "Something bad happened");
    return NULL;
}

static PyObject* snowv_initialize(PyObject *dummy, PyObject *args);
static PyObject* snowv_keystream(PyObject *dummy, PyObject *args);
static PyObject* encrypt_wrapper(PyObject *dummy, PyObject *args);
static PyObject* decrypt_wrapper(PyObject *dummy, PyObject *args);
static PyObject* gcm_encrypt(PyObject *dummy, PyObject *args);
static PyObject* gcm_decrypt(PyObject *dummy, PyObject *args);

static char snowv_initialize_doc[] = 
    "snowv_initialize(key [32 bytes], iv [16 bytes], aead_mode [uint32]) -> out [bytes]";

static char snowv_keystream_doc[] = 
    "snowv_keystream(void) -> keystream [bytes]";

static char snowv_encrypt_doc[] =
    "snowv_encrypt(key [32 bytes], iv [16 bytes], plaintext [bytes]) -> ciphertext [bytes]";

static char snowv_decrypt_doc[] =
    "snowv_decrypt(key [32 bytes], iv [16 bytes], ciphertext [bytes]) -> plaintext [bytes]";

static char gcm_encrypt_doc[] = 
    "gcm_encrypt(key [32 bytes], iv [16 bytes], plaintext [bytes], "\
    "aad [bytes]) -> Tuple [ciphertext [bytes], mac [16 bytes]]";

static char gcm_decript_doc[] = 
    "gcm_decrypt(key [32 bytes], iv [16 bytes], ciphertext [bytes], "\
    "aad [bytes], mac [bytes]) -> plaintext [bytes]";

static PyMethodDef snowv_methods[] = 
{
    //{exported name, function, args handling, doc string}
    {"error_out", (PyCFunction)error_out, METH_NOARGS, NULL},
    {"snowv_initializer", snowv_initialize, METH_VARARGS, snowv_initialize_doc},
    {"snowv_keystream", snowv_keystream, METH_NOARGS, snowv_keystream_doc},
    {"snowv_encrypt", encrypt_wrapper, METH_VARARGS, snowv_encrypt_doc},
    {"snowv_decrypt", decrypt_wrapper, METH_VARARGS, snowv_decrypt_doc},
    {"snowv_gcm_encrypt", gcm_encrypt, METH_VARARGS, gcm_encrypt_doc},
    {"snowv_gcm_decrypt", gcm_decrypt, METH_VARARGS, gcm_decript_doc},
    { NULL, NULL, 0, NULL }
};

static int snowv_traverse(PyObject *m, visitproc visit, void *arg) {
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int snowv_clear(PyObject *m) {
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "snowv",
    "bindings for SNOW-V cryptographic functions",
    sizeof(struct module_state),
    snowv_methods,
    NULL,
    snowv_traverse,
    snowv_clear,
    NULL
};

#define INITERROR return NULL

PyObject * PyInit_snowv(void)
{
    PyObject *module = PyModule_Create(&moduledef);
    if (module == NULL)
        INITERROR;
    struct module_state *st = GETSTATE(module);

    st->error = PyErr_NewException("snowv.Error", NULL, NULL);
    if (st->error == NULL)
    {
        Py_DECREF(module);
        INITERROR;
    }

    return module; 
}

// Python SNOW-V API

static PyObject* snowv_initialize(PyObject * dummy, PyObject *args)
{
    Py_buffer key_py;
    Py_buffer iv_py;
    // u8 key[32], iv[16];
    u8 out[256];
    int mode;

    if (!PyArg_ParseTuple(args, "z*z*I", &key_py, &iv_py, &mode))
        return NULL;

    if ((key_py.len != 32) || (iv_py.len != 16))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    }

    // memcpy(key, (u8 *) key_py.buf, 32);
    // memcpy(iv, (u8 *) iv_py.buf, 16);

    keyiv_setup((u8 *) key_py.buf, (u8 *) iv_py.buf, mode, out);

    return PyBytes_FromStringAndSize((char *) out, 256);
}


static PyObject* snowv_keystream(PyObject * dummy, PyObject *args)
{
    PyObject *out = 0;
    u8 z[16];
    
    keystream(z);
    out = PyBytes_FromStringAndSize((char *)z, 16);

    return out;
}

static PyObject* encrypt_wrapper(PyObject *dummy, PyObject *args)
{
    PyObject *cyphertext = 0;
    Py_buffer key, iv, plaintext;

    u64 text_sz;
    u8 *buffer;

    if (!PyArg_ParseTuple(args, "z*z*z*", &key, &iv, &plaintext))
        return NULL;

    if ((key.len != 32) || (iv.len != 16))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    }

    text_sz = (u64) plaintext.len;
    buffer = (u8 *) malloc(text_sz);

    snowv_encrypt((u8 *) key.buf, (u8 *) iv.buf, (u8 *) plaintext.buf,\
                  text_sz, buffer);
    
    cyphertext = PyBytes_FromStringAndSize((char *)buffer, text_sz);
    free(buffer);

    return cyphertext;
}

static PyObject* decrypt_wrapper(PyObject *dummy, PyObject *args)
{
    PyObject *plaintext = 0;
    Py_buffer key, iv, cyphertext;

    u64 text_sz;
    u8 *buffer;

    if (!PyArg_ParseTuple(args, "z*z*z*", &key, &iv, &cyphertext))
        return NULL;

    if ((key.len != 32) || (iv.len != 16))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;
    }

    text_sz = (u64) cyphertext.len;
    buffer = (u8 *) malloc(text_sz);

    snowv_decrypt((u8 *) key.buf, (u8 *) iv.buf, (u8 *) cyphertext.buf,\
                  text_sz, buffer);
    
    plaintext = PyBytes_FromStringAndSize((char *)buffer, text_sz);
    free(buffer);

    return plaintext;
}

static PyObject* gcm_encrypt(PyObject * dummy, PyObject *args)
{
    PyObject *cpt = 0, *mac = 0;;
    Py_buffer key, iv, plaintext_py, aad_py;

    u8 *ciphertext;
    u8 *plaintext, *aad;
    u8 *key32, *iv16;
    u8 A[16];

    u64 aad_sz, t_sz;

    if(!PyArg_ParseTuple(args, "z*z*z*z*", &key, &iv, &plaintext_py, &aad_py))
       return NULL;


    if ((key.len != 32) || (iv.len != 16))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;        
    }

    t_sz = (u64) plaintext_py.len;
    aad_sz = (u64) aad_py.len;
    key32  = (u8 *) key.buf;
    iv16 = (u8 *) iv.buf;
    plaintext = (u8 *) plaintext_py.buf;
    aad = (u8 *) aad_py.buf;
    ciphertext = (u8 *) malloc(t_sz);
    // memset(ciphertext, 0, t_sz);

    snowv_gcm_encrypt(A, ciphertext, plaintext, t_sz, aad, aad_sz, key32, iv16);
    cpt = PyBytes_FromStringAndSize((char *) ciphertext, t_sz);
    free(ciphertext);
    ciphertext = NULL;

    mac = PyBytes_FromStringAndSize((char *) A, 16);

    // Retorna uma tupla com o plaintxt e o MAC;
    return PyTuple_Pack(2, cpt, mac);
}

static PyObject* gcm_decrypt(PyObject *dummy, PyObject *args)
{
    PyObject *pnt = 0;
    Py_buffer key, iv, ciphertext_py, aad_py, mac_py;

    u8 *ciphertext;
    u8 *plaintext, *aad, *A;
    u8 *key32, *iv16;

    u64 aad_sz, t_sz;

    if(!PyArg_ParseTuple(args, "z*z*z*z*z*", &key, &iv,\
       &ciphertext_py, &aad_py, &mac_py))
       return NULL;

    if ((key.len != 32) || (iv.len != 16))
    {
        PyErr_SetString(PyExc_ValueError, "invalid args");
        return NULL;        
    }

    t_sz = (u64) ciphertext_py.len;
    aad_sz = (u64) aad_py.len;
    A = (u8 *) mac_py.buf;
    key32  = (u8 *) key.buf;
    iv16 = (u8 *) iv.buf;
    ciphertext = (u8 *) ciphertext_py.buf;
    aad = (u8 *) aad_py.buf;
    plaintext = (u8 *) malloc(t_sz);
    // memset(plaintext, 0, t_sz);

    snowv_gcm_decrypt(A, ciphertext, plaintext, t_sz, aad, aad_sz, key32, iv16);

    pnt = PyBytes_FromStringAndSize((char *) plaintext, t_sz);
    free(plaintext);
    plaintext = NULL;
    return pnt; // Retorna o plaintxt
}