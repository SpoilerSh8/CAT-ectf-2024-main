/* tls_wolfssl.h
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef  __TLS_WOLFSSL_H__
#define  __TLS_WOLFSSL_H__

#ifdef __cplusplus
extern "C" {
#endif

int wolfsslRunTests(void);
void wolfssl_client_test(uintData_t);
void wolfssl_server_test(uintData_t);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* TLS_WOLFSSL_H */
