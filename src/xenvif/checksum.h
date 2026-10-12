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

#ifndef _XENVIF_CHECKSUM_H
#define _XENVIF_CHECKSUM_H

#include "parse.h"

extern VOID
AccumulateChecksum(
    _Inout_ PULONG                      Accumulator,
    _In_reads_bytes_(ByteCount) PVOID   MappedSystemVa,
    _In_ ULONG                          ByteCount
    );

extern USHORT
ChecksumIpVersion4Header(
    _In_ PUCHAR                 StartVa,
    _In_ PXENVIF_PACKET_INFO    Info
    );

extern USHORT
ChecksumIpVersion4PseudoHeader(
    _In_ PIPV4_ADDRESS  SourceAddress,
    _In_ PIPV4_ADDRESS  DestinationAddress,
    _In_ USHORT         Length,
    _In_ UCHAR          Protocol
    );

extern USHORT
ChecksumIpVersion6PseudoHeader(
    _In_ PIPV6_ADDRESS  SourceAddress,
    _In_ PIPV6_ADDRESS  DestinationAddress,
    _In_ USHORT         Length,
    _In_ UCHAR          Protocol
    );

extern USHORT
ChecksumPseudoHeader(
    _In_ PUCHAR                 StartVa,
    _In_ PXENVIF_PACKET_INFO    Info
    );

extern USHORT
ChecksumTcpPacket(
    _In_ PUCHAR                 StartVa,
    _In_ PXENVIF_PACKET_INFO    Info,
    _In_ USHORT                 PseudoHeaderChecksum,
    _In_ PXENVIF_PACKET_PAYLOAD Payload
    );

extern USHORT
ChecksumUdpPacket(
    _In_ PUCHAR                 StartVa,
    _In_ PXENVIF_PACKET_INFO    Info,
    _In_ USHORT                 PseudoHeaderChecksum,
    _In_ PXENVIF_PACKET_PAYLOAD Payload
    );

extern BOOLEAN
ChecksumVerify(
    _In_ USHORT Calculated,
    _In_ USHORT Embedded
    );

#endif  // _XENVIF_CHECKSUM_H
