/*
 *  OpenDirectoryAuth.h
 *  OpenDirectoryAuth
 *
 *  Created by Matteo Pillon <matteo.pillon@gmail.com> on 11/08/09.
 *
 */

#ifndef OPENDIRECTORYAUTH_H
#define OPENDIRECTORYAUTH_H
#include <Python/Python.h>

static PyObject *
authenticate(PyObject *self, PyObject *args);

PyMethodDef methods[] = {
    {"authenticate", authenticate, METH_VARARGS, "authenticate(username, password)\n"
		"Authenticate user against OSX OpenDirectory service"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initOpenDirectoryAuth();


#endif
