/* Copyright (c) Xen Project.
 * Copyright (c) Cloud Software Group, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, 
 * with or without modification, are permitted provided 
 * that the following conditions are met:
 * 
 * *   Redistributions of source code must retain the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above 
 *     copyright notice, this list of conditions and the 
 *     following disclaimer in the documentation and/or other 
 *     materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND 
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR 
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE.
 */

#ifndef _LLC_H
#define _LLC_H

#pragma warning(push)
#pragma warning(disable:4214) // nonstandard extension used : bit field types other than int
#pragma warning(disable:4201) // nonstandard extension used : nameless struct/union

#pragma pack(push, 1)

// LLC data structures
//
// NOTE: Fields are in network byte order

typedef struct _LLC_U_HEADER {
    UCHAR   DestinationSAP;
    UCHAR   SourceSAP;
    UCHAR   Control;
} LLC_U_HEADER, *PLLC_U_HEADER;

#define LLC_SAP_MASK (~(UCHAR)1)
#define LLC_U_FRAME 0x03

typedef struct _LLC_SNAP_HEADER {
    UCHAR   DestinationSAP;
    UCHAR   SourceSAP;
    UCHAR   Control;
    UCHAR   OUI[3];
    USHORT  Type;
} LLC_SNAP_HEADER, *PLLC_SNAP_HEADER;

#define SNAPTYPE_IPX    0x8137
#define SNAPTYPE_IPV4   ETHERTYPE_IPV4
#define SNAPTYPE_IPV6   ETHERTYPE_IPV6

#pragma pack(pop)

#pragma warning(pop)

#endif  //_LLC_H
